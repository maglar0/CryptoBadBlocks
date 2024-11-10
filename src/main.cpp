#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <sstream>
#include <random>
#include <cstdint>
#include <array>
#include <optional>
#include <functional>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <cstring>

#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>

#ifdef __APPLE__
#include <CommonCrypto/CommonCrypto.h>
#include <Security/Security.h>
#elif defined(__linux__)
#include <openssl/evp.h>
#include <openssl/rand.h>
#endif


#ifdef __APPLE__
#include <sys/disk.h>
#elif defined(__linux__)
#include <linux/fs.h>
#endif

#ifdef __APPLE__
#include <mach/mach_time.h>
#elif defined(__linux__)
#include <ctime> 
#endif


const std::uint32_t kAES128KeySize = 128/8;
const std::uint32_t kAESBlockSize = 128/8;

typedef std::array<std::uint8_t, kAES128KeySize> TAESKey;
typedef std::array<std::uint8_t, kAESBlockSize> TAESBlock;


#define EXPECT(condition, message) \
    do { \
        if (!(condition)) { \
            throw std::runtime_error(std::string("EXPECT failure - ") +  __FUNCTION__ +  ":" + (message)); \
        } \
    } while (0)

template <typename T, std::size_t Alignment>
struct CAlignedAllocator
{
    using value_type = T;

    CAlignedAllocator() = default;

    template <typename U>
    constexpr CAlignedAllocator(const CAlignedAllocator<U, Alignment> &) noexcept {}

    T *allocate(std::size_t n)
    {
        // Ensure size is a multiple of alignment (required by std::aligned_alloc)
        std::size_t size = n * sizeof(T);
        if (size % Alignment != 0)
        {
            size += Alignment - (size % Alignment);
        }
        return static_cast<T *>(std::aligned_alloc(Alignment, size));
    }

    void deallocate(T *ptr, std::size_t) noexcept
    {
        std::free(ptr);
    }

    // Required for compatibility with standard containers
    template <typename U>
    struct rebind
    {
        using other = CAlignedAllocator<U, Alignment>;
    };
};

template <typename T, std::size_t Alignment>
bool operator==(const CAlignedAllocator<T, Alignment> &, const CAlignedAllocator<T, Alignment> &)
{
    return true;
}

template <typename T, std::size_t Alignment>
bool operator!=(const CAlignedAllocator<T, Alignment> &, const CAlignedAllocator<T, Alignment> &)
{
    return false;
}

class CAESECB
{
public:
    CAESECB(const TAESKey& key)
        : m_key(key)
    {
    }

    bool Encrypt(const TAESBlock& inBlock, TAESBlock& outBlock) const {
        size_t outLength = 0;

#ifdef __APPLE__
        CCCryptorStatus status = CCCrypt(kCCEncrypt, kCCAlgorithmAES128, kCCOptionECBMode,
                                         m_key.data(), m_key.size(),
                                         nullptr, // No initialization vector for ECB
                                         inBlock.data(), inBlock.size(),
                                         outBlock.data(), outBlock.size(),
                                         &outLength);

        if (status != kCCSuccess) {
            std::cerr << __FUNCTION__ << ": CCCrypt failed with status " << status << std::endl;
            // Print the error message

            return false;
        }

#elif defined(__linux__)
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return false;

        if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, m_key.data(), nullptr)) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }

        if (1 != EVP_EncryptUpdate(ctx, outBlock.data(), (int*)&outLength, inBlock.data(), inBlock.size())) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }

        if (1 != EVP_EncryptFinal_ex(ctx, outBlock.data() + outLength, (int*)&outLength)) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }

        EVP_CIPHER_CTX_free(ctx);
#else
#error
#endif


        if (outLength != outBlock.size()) {
            std::cerr << __FUNCTION__ << ": Unexpected output length " << outLength << std::endl;
            return false;
        }

        return true;
    }

private:
    TAESKey m_key;
};


class CAESCTR
{
public:
    CAESCTR(const TAESKey &key)
        : m_key(key)
    {
    }

    bool Encrypt(const uint8_t* input, uint8_t* output, size_t length, std::uint64_t iv) const {
        return Process(input, output, length, iv, EOperation::Encrypt);
    }

    bool Decrypt(const uint8_t* input, uint8_t* output, size_t length, std::uint64_t iv) const {
        return Process(input, output, length, iv, EOperation::Decrypt);
    }

private:

    enum class EOperation {
        Encrypt,
        Decrypt
    };

    bool Process(const uint8_t* input, uint8_t* output, size_t length, std::uint64_t iv, EOperation operation) const {
        size_t outLength = 0;
        TAESBlock ivBlock = {};
        std::copy(reinterpret_cast<const std::uint8_t*>(&iv), reinterpret_cast<const std::uint8_t*>(&iv) + sizeof(iv), ivBlock.begin());

#ifdef __APPLE__
        CCOperation op = operation == EOperation::Encrypt ? kCCEncrypt : kCCDecrypt;
        CCCryptorStatus status = CCCrypt(op, kCCAlgorithmAES128, kCCModeCTR,
                                         m_key.data(), m_key.size(),
                                         ivBlock.data(),
                                         input, length,
                                         output, length,
                                         &outLength);

        if (status != kCCSuccess) {
            std::cerr << __FUNCTION__ << ": CCCrypt failed with status " << status << std::endl;
            return false;
        }

#elif defined(__linux__)
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return false;

        if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), nullptr, m_key.data(), ivBlock.data())) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }

        if (1 != EVP_EncryptUpdate(ctx, output, (int*)&outLength, input, length)) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }

        EVP_CIPHER_CTX_free(ctx);

#else
#error
#endif

        if (outLength != length) {
            std::cerr << __FUNCTION__ << ": Unexpected output length " << outLength << std::endl;
            return false;
        }

        return true;
    }

    TAESKey m_key;
};


bool FeistelEncrypt(const CAESECB& cipher, std::uint32_t numRounds, std::uint32_t sizeInBits, std::uint64_t input, std::uint64_t &output)
{
    if (sizeInBits % 2 != 0 || sizeInBits == 0 || sizeInBits > 64)
    {
        std::cerr << __FUNCTION__ << ": Invalid sizeInBits - " << sizeInBits << std::endl;
        return false;
    }
    if (numRounds < 3)
    {
        std::cerr << __FUNCTION__ << ": Must be at least 3 rounds" << std::endl;
        return false;
    }

    const std::uint32_t halfSizeInBits = sizeInBits / 2;
    const std::uint64_t leftMask = (1ULL << halfSizeInBits) - 1; // Mask to extract the left half
    const std::uint64_t rightMask = leftMask;                    // Mask to extract the right half

    std::uint64_t left = (input >> halfSizeInBits) & leftMask;
    std::uint64_t right = input & rightMask;

    for (std::uint32_t round = 0; round < numRounds; ++round)
    {
        TAESBlock inputBlock = {};
        TAESBlock outputBlock = {};

        std::copy(reinterpret_cast<const std::uint8_t*>(&right), reinterpret_cast<const std::uint8_t*>(&right) + sizeof(right), inputBlock.begin());
        std::copy(reinterpret_cast<const std::uint8_t*>(&round), reinterpret_cast<const std::uint8_t*>(&round) + sizeof(round), inputBlock.begin() + sizeof(right));

        if (!cipher.Encrypt(inputBlock, outputBlock))
        {
            std::cerr << __FUNCTION__ << ": AES encryption failed" << std::endl;
            return false;
        }

        std::uint64_t transformedRight;
        std::copy(outputBlock.data(), outputBlock.data() + sizeof(transformedRight), reinterpret_cast<std::uint8_t *>(&transformedRight));
        std::uint64_t newLeft = right;
        right = left ^ transformedRight; // Feistel function: L_i = R_{i-1} XOR f(R_{i-1})
        right &= rightMask;
        left = newLeft; // Update left half for the next round

        // Print round, left (hex), right (hex), transformedRight (hex)
        // std::cout << "  Round " << round
        //    << ": " << std::hex << std::setw(2) << std::setfill('0') << left
        //    << " " << std::hex << std::setw(2) << std::setfill('0') << right
        //    << " " << std::hex << std::setw(2) << std::setfill('0') << transformedRight << std::endl;
    }

    output = (right << halfSizeInBits) | left;
    // std::cout << " Output: " << std::dec << output << std::endl;

    // Consistency check, output should always be less than 2^sizeInBits
    if (output >= (1ULL << sizeInBits))
    {
        std::cerr << __FUNCTION__ << ": Invalid output " << output << std::endl;
        return false;
    }

    return true;
}

// Encrypts an index in the range [0, size) using a Feistel network. This ensures that the output
// will be in [0, size), and each index will have a unique output, and it will be
// non-trivial to determine the original index from the output. And everything is deterministic.
bool EncryptIndex(const CAESECB& cipher, std::uint64_t index, std::uint64_t size, std::uint64_t& output)
{
    if (size == 0)
    {
        std::cerr << __FUNCTION__ << ": Invalid size " << size << std::endl;
        return false;
    }
    if (index >= size)
    {
        std::cerr << __FUNCTION__ << ": Index " << index << " larger than size " << size << std::endl;
        return false;
    }
    // Arbitrary sanity check to avoid edge cases
    if (size > 1ULL << 60)
    {
        std::cerr << __FUNCTION__ << ": Size " << size << " too large" << std::endl;
        return false;
    }

    // Calculate the smallest even power of 2 that is greater than or equal to size
    std::uint64_t sizeInBits = 2;
    while (1ULL << sizeInBits < size)
    {
        sizeInBits += 2;
    }

    std::uint64_t randomizedIndex = index;
    do
    {
        const std::uint32_t numRounds = 3;
        if (!FeistelEncrypt(cipher, numRounds, sizeInBits, randomizedIndex, randomizedIndex))
        {
            std::cerr << __FUNCTION__ << ": FeistelEncrypt failed" << std::endl;
            return false;
        }
        if (randomizedIndex >= 1ULL << sizeInBits)
        {
            std::cerr << __FUNCTION__ << ": Invalid randomized index " << randomizedIndex << std::endl;
            return false;
        }
    } while (randomizedIndex >= size);

    output = randomizedIndex;
    return true;
}

TAESKey GenerateKeyFromString(const std::string& input, std::uint32_t numKeys)
{
    std::uint8_t hash[256/8];

#ifdef __APPLE__
    CC_SHA256(input.c_str(), static_cast<CC_LONG>(input.length()), hash);
#elif defined(__linux__)
    EVP_Digest(input.c_str(), input.length(), hash, nullptr, EVP_sha256(), nullptr);
#endif

    TAESKey key = {};
    std::copy(hash, hash + kAES128KeySize, key.begin());

    return key;
}

std::string ToHex(const std::uint8_t* data, size_t length)
{
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < length; ++i)
    {
        oss << std::setw(2) << static_cast<int>(data[i]);
    }
    return oss.str();
}

class CHighResTimer
{
public:
    CHighResTimer()
    {
#ifdef __APPLE__
        start_time = mach_absolute_time();
        mach_timebase_info(&timebase_info);
#elif defined(__linux__)
        clock_gettime(CLOCK_MONOTONIC, &start_time_linux);
#endif
    }

    CHighResTimer(const CHighResTimer&) = delete;
    CHighResTimer& operator=(const CHighResTimer&) = delete;

    uint64_t GetElapsedNanoseconds() const
    {
#ifdef __APPLE__
        uint64_t end_time = mach_absolute_time();
        uint64_t elapsed_ticks = end_time - start_time;
        // Convert elapsed ticks to nanoseconds using timebase_info
        return elapsed_ticks * timebase_info.numer / timebase_info.denom;
#elif defined(__linux__)
        // On Linux, use clock_gettime to calculate elapsed time
        struct timespec end_time_linux;
        clock_gettime(CLOCK_MONOTONIC, &end_time_linux);
        
        uint64_t elapsed_ns = (end_time_linux.tv_sec - start_time_linux.tv_sec) * 1000000000L + 
                               (end_time_linux.tv_nsec - start_time_linux.tv_nsec);
        return elapsed_ns;
#endif
    }

#ifdef __APPLE__
    uint64_t start_time;
    mach_timebase_info_data_t timebase_info;
#elif defined(__linux__)
    struct timespec start_time_linux;
#endif
};


class CPeriodicTimer
{
public:
    CPeriodicTimer(std::uint64_t periodInNanoseconds)
        : m_periodInNanoseconds(periodInNanoseconds)
    {
        EXPECT(periodInNanoseconds > 0, "Period must be greater than zero");
        m_lastTime = m_timer.GetElapsedNanoseconds();
    }

    bool IsTimeToRun() {
        std::uint64_t currentTime = m_timer.GetElapsedNanoseconds();
        
        std::uint64_t currentCycle = currentTime / m_periodInNanoseconds;
        std::uint64_t lastCycle = m_lastTime / m_periodInNanoseconds;
        if (currentCycle > lastCycle) {
            m_lastTime = currentTime;
            return true;
        }
        return false;
    }

private:
    CHighResTimer       m_timer;
    std::uint64_t       m_periodInNanoseconds = 0;
    std::uint64_t       m_lastTime = 0;
};

class CBytesPerSecondEstimator
{
public:
    
    void Update(std::uint64_t totalNumBytes)
    {
        std::uint64_t currentTime = m_timer.GetElapsedNanoseconds();
        std::uint64_t elapsedTime = currentTime - m_lastEstimationTime;
        if (elapsedTime < 500 * 1000 * 1000) { // 500 ms
            return;
        }

        std::uint64_t bytesSinceLastEstimation = totalNumBytes - m_numBytesAtLastEstimation;
        double bytesPerSecond = static_cast<double>(bytesSinceLastEstimation) / elapsedTime * 1000 * 1000 * 1000;
        double oldWeight = m_lastEstimationTime == 0 ? 0.0 : 0.25;
        double newWeight = 1.0 - oldWeight;
        m_lastEstimationBytesPerSecond = m_lastEstimationBytesPerSecond * oldWeight + bytesPerSecond * newWeight;

        m_numBytesAtLastEstimation = totalNumBytes;
        m_lastEstimationTime = currentTime;
    }

    double GetBytesPerSecondEstimation() const {
        return m_lastEstimationBytesPerSecond;
    }

private : 
    CHighResTimer m_timer;
    std::uint64_t       m_lastEstimationTime = 0;
    std::uint64_t       m_numBytesAtLastEstimation = 0;
    double              m_lastEstimationBytesPerSecond = 0;
};


struct Options
{
    std::uint64_t blockSize = 1024 * 1024; // default 1M
    std::optional<std::uint64_t> count;
    double overlap = 0;
    bool resume = false;
    std::optional<std::string> seed;
    std::optional<std::string> pattern;
    bool linear = false;
    bool noGraphs = false;
    std::string summaryFile;
    std::string device;
};

class CFileDescriptor
{
public:
    explicit CFileDescriptor(int fd) : m_fd(fd) {}

    CFileDescriptor(const CFileDescriptor &) = delete;
    CFileDescriptor &operator=(const CFileDescriptor &) = delete;

    CFileDescriptor(CFileDescriptor &&other) noexcept : m_fd(std::exchange(other.m_fd, -1)) {}

    // Move assignment operator
    CFileDescriptor &operator=(CFileDescriptor &&other) noexcept
    {
        if (this != &other)
        {
            Close();
            m_fd = std::exchange(other.m_fd, -1);
        }
        return *this;
    }

    ~CFileDescriptor()
    {
        Close();
    }

    int Get() const { return m_fd; }

private:
    int m_fd;

    void Close() {
        if (m_fd >= 0) {
            ::close(m_fd);
        }
    }
};

CFileDescriptor OpenDevice(const std::string& devicePath) {
    int flags = O_RDWR | O_SYNC;
#ifdef __linux__
    flags |= O_DIRECT;
#endif // __linux__
    int fd = ::open(devicePath.c_str(), flags);
    if (fd < 0) {
        throw std::runtime_error("Error: Failed to open device " + devicePath);
    }
    return CFileDescriptor(fd);
}


std::uint64_t GetDeviceSize(int fd)
{
    std::uint64_t size = 0;

#if defined(__linux__)
    if (ioctl(fd, BLKGETSIZE64, &size) != 0) {
        throw std::runtime_error("Error getting device size");
    }
#elif defined(__APPLE__)
    unsigned long blockSize = 0;
    unsigned long blockCount = 0;
    if (ioctl(fd, DKIOCGETBLOCKSIZE, &blockSize) == 0 &&
        ioctl(fd, DKIOCGETBLOCKCOUNT, &blockCount) == 0)
    {
        size = static_cast<std::uint64_t>(blockSize) * blockCount;
    }
    else {
        throw std::runtime_error("Error getting device size");
    }
#endif

    return size;
}


std::uint32_t GetBlockSize(int fd)
{
    std::uint32_t blockSize = 0;

#if defined(__linux__)
    if (ioctl(fd, BLKSSZGET, &blockSize) != 0) {
        throw std::runtime_error("Error getting device block size");
    }
#elif defined(__APPLE__)
    if (ioctl(fd, DKIOCGETBLOCKSIZE, &blockSize) != 0) {
        throw std::runtime_error("Error getting device block size");
    }
#endif

    return blockSize;
}


std::vector<std::pair<std::uint64_t, std::uint64_t> > CalculateRanges(
    const std::vector<std::uint64_t>& sortedOffsets, 
    std::uint64_t blockSize,
    std::uint64_t deviceSize)
{
    EXPECT(blockSize > 0, "blockSize must be greater than zero");
    EXPECT(std::is_sorted(sortedOffsets.begin(), sortedOffsets.end()), "sortedOffsets is not sorted");

    std::vector<std::pair<std::uint64_t, std::uint64_t> > ranges;
    if (sortedOffsets.empty()) {
        return ranges;
    }

    std::uint64_t start = sortedOffsets.front();
    std::uint64_t end = start + blockSize;
    for (size_t i = 1; i < sortedOffsets.size(); ++i) {
        if (sortedOffsets[i] == end) {
            end += blockSize;
        }
        else {
            ranges.emplace_back(start, end);
            start = sortedOffsets[i];
            end = start + blockSize;
        }
    }
    if (end > deviceSize) {
        end = deviceSize;
    }
    ranges.emplace_back(start, end);
    return ranges;
}


std::string FormatTime(std::uint32_t seconds)
{
    std::uint32_t hours = seconds / 3600;
    std::uint32_t minutes = (seconds % 3600) / 60;
    std::uint32_t secs = seconds % 60;

    std::ostringstream oss;
    if (hours > 0)
    {
        oss << std::setw(2) << std::setfill('0') << hours << ":";
    }
    oss << std::setw(2) << std::setfill('0') << minutes << ":"
        << std::setw(2) << std::setfill('0') << secs;

    return oss.str();
}

class CMain {

public:

    CMain(const std::string& devicePath) 
        : m_deviceFileDescriptor(OpenDevice(devicePath))
        , m_workerThread([this] { WorkerThread(); })
    {
    }

    ~CMain() {
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            m_workQueue.emplace_back(std::make_unique<WorkItem>());
            m_conditionVariable.notify_one();
        }
        m_workerThread.join();
    }

    CMain(const CMain&) = delete;
    CMain& operator=(const CMain&) = delete;




    void Mainloop(const TAESKey& iterationOrderKey, const TAESKey& dataKey, const Options& options) {
        const CAESECB iterationOrderCipher(iterationOrderKey);
        const CAESCTR dataCipher(dataKey);

        const std::uint64_t deviceSize = GetDeviceSize(m_deviceFileDescriptor.Get());
        const std::uint64_t deviceBlockSize = GetBlockSize(m_deviceFileDescriptor.Get());
        if (options.blockSize % deviceBlockSize != 0) {
            throw std::invalid_argument("Error: Block size must be a multiple of the device block size (" + std::to_string(deviceBlockSize) + ")");
        }

        std::vector<std::unique_ptr<WorkItem>> workItemBuffer;
        workItemBuffer.emplace_back(std::make_unique<WorkItem>());
        workItemBuffer.emplace_back(std::make_unique<WorkItem>());
        workItemBuffer.emplace_back(std::make_unique<WorkItem>());

        std::uint64_t numQueuedWorkItems = 0;
        const std::vector<std::uint8_t> zeros(options.blockSize);
        std::vector<std::uint8_t> verificationBuffer(options.blockSize);

        // We have two things known as "block size", the device block size and the test block size. But from now on, block
        // always refers to the test blocks. Calculate the number of blocks on the device (rounding up, to cover the whole device). 
        const std::uint64_t numBlocksOnDevice = (deviceSize + options.blockSize - 1) / options.blockSize;
        const std::uint64_t numBlocksToTest = options.count.value_or(numBlocksOnDevice);
        const std::uint64_t lastBlockSize = deviceSize - (numBlocksOnDevice - 1) * options.blockSize;

        std::vector<std::uint32_t> writeLatencyInMicroseconds;
        std::vector<std::uint32_t> readLatencyInMicroseconds;
        writeLatencyInMicroseconds.reserve(numBlocksToTest);
        readLatencyInMicroseconds.reserve(numBlocksToTest);

        std::vector<std::uint64_t> readFailureOffsets;
        std::vector<std::uint64_t> writeFailureOffsets;
        std::vector<std::uint64_t> verificationFailureOffsets;
        readFailureOffsets.reserve(numBlocksToTest);
        writeFailureOffsets.reserve(numBlocksToTest);
        verificationFailureOffsets.reserve(numBlocksToTest);

        // An update will be printed every second, and it will print using "\r" to overwrite the previous line,
        // so we need to make an empty line for it for the first update.
        std::cout << std::endl;

        std::uint64_t totalBytesWritten = 0;
        std::uint64_t totalBytesRead = 0;

        CBytesPerSecondEstimator bytesPerSecondEstimator;
        CPeriodicTimer periodicTimer(1000 * 1000 * 1000); // 1 second
        CHighResTimer totalTimer;

        std::uint64_t writeIndex = 0;
        std::uint64_t readIndex = 0;
        do {
            if (writeIndex < numBlocksToTest) {
                std::uint64_t randomizedIndex = 0xFFFFFFFFFFFFFFFF;
                if (options.linear) {
                    randomizedIndex = writeIndex;
                }
                else if (!EncryptIndex(iterationOrderCipher, writeIndex, numBlocksOnDevice, randomizedIndex)) {
                    throw std::runtime_error("Error: Failed to encrypt index " + std::to_string(writeIndex));
                }

                EXPECT(!workItemBuffer.empty(), "workItemBuffer is empty, with numQueuedWorkItems = " + std::to_string(numQueuedWorkItems));
                std::unique_ptr<WorkItem> workItem;
                workItem.swap(workItemBuffer.back());
                workItemBuffer.pop_back();

                workItem->offset = randomizedIndex * options.blockSize;
                workItem->operation = Operation::Write;
                workItem->success = false;
                workItem->durationInNanoseconds = 0;

                bool isLastBlock = randomizedIndex == numBlocksOnDevice - 1;
                std::uint64_t size = isLastBlock ? lastBlockSize : options.blockSize;
                workItem->data.resize(size);
                std::uint64_t iv = workItem->offset;
                bool success = dataCipher.Encrypt(zeros.data(), workItem->data.data(), size, iv);
                if (!success) {
                    throw std::runtime_error("Error: Failed to encrypt data for block " + std::to_string(randomizedIndex));
                }

                {
                    std::unique_lock<std::mutex> lock(m_mutex);
                    m_workQueue.push_back(std::move(workItem));
                    m_conditionVariable.notify_one();
                    numQueuedWorkItems++;
                }

                writeIndex++;
            }

            bool read = false;
            if (readIndex < numBlocksToTest) {
                if (writeIndex == numBlocksToTest) {
                    read = true;
                }
                else if (options.overlap > 0)
                {
                    read = readIndex < writeIndex * options.overlap / 100.0;
                }
            }

            if (read) {
                std::uint64_t randomizedIndex = 0xFFFFFFFFFFFFFFFF;
                if (options.linear) {
                    randomizedIndex = readIndex;
                }
                else if (!EncryptIndex(iterationOrderCipher, readIndex, numBlocksOnDevice, randomizedIndex)) {
                    throw std::runtime_error("Error: Failed to encrypt index " + std::to_string(readIndex));
                }

                EXPECT(!workItemBuffer.empty(), "workItemBuffer is empty, with numQueuedWorkItems = " + std::to_string(numQueuedWorkItems) + 
                                                " and readIndex = " + std::to_string(readIndex));
                std::unique_ptr<WorkItem> workItem;
                workItem.swap(workItemBuffer.back());
                workItemBuffer.pop_back();

                workItem->offset = randomizedIndex * options.blockSize;
                workItem->operation = Operation::Read;
                workItem->success = false;
                workItem->durationInNanoseconds = 0;

                bool isLastBlock = randomizedIndex == numBlocksOnDevice - 1;
                std::uint64_t size = isLastBlock ? lastBlockSize : options.blockSize;
                workItem->data.resize(size);

                {
                    std::unique_lock<std::mutex> lock(m_mutex);
                    m_workQueue.push_back(std::move(workItem));
                    m_conditionVariable.notify_one();
                    numQueuedWorkItems++;
                }

                readIndex++;
            }

            while (numQueuedWorkItems >= 2 || (numQueuedWorkItems > 0 && readIndex == numBlocksToTest)) {
                std::unique_ptr<WorkItem> workItem;
                {
                    std::unique_lock<std::mutex> lock(m_mutex);
                    m_conditionVariable.wait(lock, [this] { return !m_resultQueue.empty() || !m_workerThreadError.empty(); });
                    if (!m_workerThreadError.empty()) {
                        throw std::runtime_error(m_workerThreadError);
                    }

                    EXPECT(!m_resultQueue.empty(), "m_resultQueue is empty");
                    workItem.swap(m_resultQueue.front());
                    m_resultQueue.erase(m_resultQueue.begin());
                    numQueuedWorkItems--;
                }

                const std::uint64_t blockIndex = workItem->offset / options.blockSize;

                if (workItem->operation == Operation::Write) {
                    if (!workItem->success) {
                        writeFailureOffsets.push_back(workItem->offset);
                    }
                    writeLatencyInMicroseconds.push_back(workItem->durationInNanoseconds/1000);
                    totalBytesWritten += workItem->data.size();
                }
                else {
                    if (!workItem->success) {
                        readFailureOffsets.push_back(workItem->offset);
                    }
                    else {
                        std::uint64_t iv = workItem->offset;
                        EXPECT(workItem->data.size() <= verificationBuffer.size(), "workItem->data.size() > verificationBuffer.size()");
                        bool success = dataCipher.Decrypt(workItem->data.data(), verificationBuffer.data(), workItem->data.size(), iv);
                        if (!success) {
                            throw std::runtime_error("Error: Failed to decrypt data for block " + std::to_string(blockIndex));
                        }
                        if (std::memcmp(zeros.data(), verificationBuffer.data(), workItem->data.size()) != 0) {
                            verificationFailureOffsets.push_back(workItem->offset);
                        }
                    }
                    readLatencyInMicroseconds.push_back(workItem->durationInNanoseconds/1000);
                    totalBytesRead += workItem->data.size();
                }
                workItemBuffer.push_back(std::move(workItem));
            }

            if (periodicTimer.IsTimeToRun() || numQueuedWorkItems == 0) {
                std::uint32_t elapsedSeconds = totalTimer.GetElapsedNanoseconds() / 1000 / 1000 / 1000;

                bytesPerSecondEstimator.Update(totalBytesWritten + totalBytesRead);
                double bytesPerSecond = bytesPerSecondEstimator.GetBytesPerSecondEstimation();
                std::uint64_t bytesLeft = (numBlocksToTest * 2 - writeIndex - readIndex) * options.blockSize;
                std::uint32_t secondsLeft = bytesLeft / bytesPerSecond;

                // Multiply by 1000 and dividing by 1000.0 to round down.
                double progress = (writeIndex + readIndex) * 1000 / (numBlocksToTest * 2) / 1000.0;

                std::cout << "\rProgress: " << std::fixed << std::setprecision(1) << 100.0 * progress << " %"
                    << " (" << writeFailureOffsets.size() << "/" 
                    << readFailureOffsets.size() << "/" 
                    << verificationFailureOffsets.size() 
                    << " w/r/v failures)"
                    << " in " << FormatTime(elapsedSeconds)
                    << ", " << std::fixed << std::setprecision(1) << bytesPerSecond / 1024 / 1024 << " MiB/s"
                    << ", " << FormatTime(secondsLeft) << " left"
                    << std::flush;
            }

        } while (numQueuedWorkItems > 0);

        const double totalTestTimeInSeconds = totalTimer.GetElapsedNanoseconds() / 1000.0 / 1000.0 / 1000.0;
        const double totalWriteTimeInSeconds = std::accumulate(writeLatencyInMicroseconds.begin(), writeLatencyInMicroseconds.end(), 0.0) / 1000.0 / 1000.0;
        const double totalReadTimeInSeconds = std::accumulate(readLatencyInMicroseconds.begin(), readLatencyInMicroseconds.end(), 0.0) / 1000.0 / 1000.0;

        std::cout << std::endl;

        std::sort(writeLatencyInMicroseconds.begin(), writeLatencyInMicroseconds.end());
        std::cout << "Write latency (ms): " << std::fixed << std::setprecision(1) << "\n"
                    << "  Min: " << writeLatencyInMicroseconds.front() / 1000.0 << "\n"
                    << "  Max: " << writeLatencyInMicroseconds.back() / 1000.0 << "\n"
                    << "  1 %: " << writeLatencyInMicroseconds[writeLatencyInMicroseconds.size() / 100] / 1000.0 << "\n"
                    << "  10 %: " << writeLatencyInMicroseconds[writeLatencyInMicroseconds.size() / 10] / 1000.0 << "\n"
                    << "  50 %: " << writeLatencyInMicroseconds[writeLatencyInMicroseconds.size() / 2] / 1000.0 << "\n"
                    << "  90 %: " << writeLatencyInMicroseconds[writeLatencyInMicroseconds.size() * 9 / 10] / 1000.0 << "\n"
                    << "  99 %: " << writeLatencyInMicroseconds[writeLatencyInMicroseconds.size() * 99 / 100] / 1000.0 << "\n"
                    << "  Avg: " << totalWriteTimeInSeconds * 1000.0 / writeLatencyInMicroseconds.size() << std::endl;
        std::cout << "Write speed: " << std::fixed << std::setprecision(1) << totalBytesWritten / totalWriteTimeInSeconds / 1024.0 / 1024.0 << " MiB/s" << std::endl;

        std::sort(readLatencyInMicroseconds.begin(), readLatencyInMicroseconds.end());
        std::cout << "Read latency (ms): " << std::fixed << std::setprecision(1) << "\n"
                    << "  Min: " << readLatencyInMicroseconds.front() / 1000.0 << "\n"
                    << "  Max: " << readLatencyInMicroseconds.back() / 1000.0 << "\n"
                    << "  1 %: " << readLatencyInMicroseconds[readLatencyInMicroseconds.size() / 100] / 1000.0 << "\n"
                    << "  10 %: " << readLatencyInMicroseconds[readLatencyInMicroseconds.size() / 10] / 1000.0 << "\n"
                    << "  50 %: " << readLatencyInMicroseconds[readLatencyInMicroseconds.size() / 2] / 1000.0 << "\n"
                    << "  90 %: " << readLatencyInMicroseconds[readLatencyInMicroseconds.size() * 9 / 10] / 1000.0 << "\n"
                    << "  99 %: " << readLatencyInMicroseconds[readLatencyInMicroseconds.size() * 99 / 100] / 1000.0 << "\n"
                    << "  Avg: " << totalReadTimeInSeconds * 1000.0 / readLatencyInMicroseconds.size() << std::endl;
        std::cout << "Read speed: " << std::fixed << std::setprecision(1) << totalBytesRead / totalReadTimeInSeconds / 1024.0 / 1024.0 << " MiB/s" << std::endl;

        std::cout << "Total time: " << std::fixed << std::setprecision(1) << totalTestTimeInSeconds << " s" << std::endl;
        std::cout << "  of which: " << std::fixed << std::setprecision(1) << totalWriteTimeInSeconds << " s writing \n" 
                  << "            " << totalReadTimeInSeconds << " s reading\n"
                  << "            " << totalWriteTimeInSeconds + totalReadTimeInSeconds << " s reading/writing" << std::endl;

        std::sort(writeFailureOffsets.begin(), writeFailureOffsets.end());
        std::sort(readFailureOffsets.begin(), readFailureOffsets.end());
        std::sort(verificationFailureOffsets.begin(), verificationFailureOffsets.end());

        std::vector<std::pair<std::uint64_t, std::uint64_t> > writeFailureRanges = CalculateRanges(writeFailureOffsets, options.blockSize, deviceSize);
        std::vector<std::pair<std::uint64_t, std::uint64_t> > readFailureRanges = CalculateRanges(readFailureOffsets, options.blockSize, deviceSize);
        std::vector<std::pair<std::uint64_t, std::uint64_t> > verificationFailureRanges = CalculateRanges(verificationFailureOffsets, options.blockSize, deviceSize);

        std::cout << "Write failures: " << writeFailureOffsets.size() << std::endl;
        std::cout << "Read failures: " << readFailureOffsets.size() << std::endl;
        std::cout << "Verification failures: " << verificationFailureOffsets.size() << std::endl;
        size_t numFailureRanges = writeFailureRanges.size() + readFailureRanges.size() + verificationFailureRanges.size();
        if (numFailureRanges > 0 && numFailureRanges < 50) {
            std::cout << "Failure ranges (in bytes from start of device): " << std::endl;
            std::cout << "  Write:" << std::endl;
            for (const auto& range : writeFailureRanges) {
                std::cout << "    " << range.first << " - " << range.second << std::endl;
            }
            std::cout << "  Read:" << std::endl;
            for (const auto& range : readFailureRanges) {
                std::cout << "    " << range.first << " - " << range.second << std::endl;
            }
            std::cout << "  Verification:" << std::endl;
            for (const auto& range : verificationFailureRanges) {
                std::cout << "    " << range.first << " - " << range.second << std::endl;
            }
        }
    }

private:
    enum class Operation
    {
        Write,
        Read
    };

    struct WorkItem
    {
        std::uint64_t offset = 0xFFFFFFFFFFFFFFFF; // Offset from start of device in bytes for the operation.
        Operation operation = Operation::Read;
        std::vector<std::uint8_t, CAlignedAllocator<std::uint8_t, 8192>> data; // Usually block size data, but smaller on last block, and empty when we're done.
        bool success = false;
        std::uint64_t durationInNanoseconds = 0;

        // We don't want to copy or assign WorkItem to avoid inadvertently copying large data buffers.
        void operator=(const WorkItem &other) = delete;
        WorkItem(const WorkItem &other) = delete;
        WorkItem() = default;
    };


    void WorkerThread() {
        try {
            while (true) {
                std::unique_ptr<WorkItem> workItem;
                {
                    std::unique_lock<std::mutex> lock(m_mutex);
                    m_conditionVariable.wait(lock, [this] { return !m_workQueue.empty(); });
                    workItem.swap(m_workQueue.front());
                    m_workQueue.erase(m_workQueue.begin());
                }

                if (workItem->data.empty()) {
                    break;
                }

                std::uint64_t newOffset = lseek(m_deviceFileDescriptor.Get(), workItem->offset, SEEK_SET);
                if (newOffset != workItem->offset) {
                    workItem->success = false;
                    workItem->durationInNanoseconds = 0;
                }
                else if (workItem->operation == Operation::Write) {
                    CHighResTimer timer;
                    int result = write(m_deviceFileDescriptor.Get(), workItem->data.data(), workItem->data.size());
                    fsync(m_deviceFileDescriptor.Get());
                    workItem->durationInNanoseconds = timer.GetElapsedNanoseconds();
                    workItem->success = result == static_cast<ssize_t>(workItem->data.size());
                }
                else {
                    CHighResTimer timer;
                    int result = read(m_deviceFileDescriptor.Get(), workItem->data.data(), workItem->data.size());;
                    workItem->durationInNanoseconds = timer.GetElapsedNanoseconds();
                    workItem->success = result == static_cast<ssize_t>(workItem->data.size());
                }

                {
                    std::unique_lock<std::mutex> lock(m_mutex);
                    m_resultQueue.push_back(std::move(workItem));
                    m_conditionVariable.notify_one();
                }
            }
        } 
        catch (const std::exception &e) {
            std::unique_lock<std::mutex> lock(m_mutex);
            m_workerThreadError = e.what();
            m_conditionVariable.notify_one();
        }
    }

    CFileDescriptor                             m_deviceFileDescriptor;
    std::thread                                 m_workerThread;

    std::vector<std::unique_ptr<WorkItem> >     m_workQueue;
    std::vector<std::unique_ptr<WorkItem> >     m_resultQueue;
    std::string                                 m_workerThreadError;
    std::mutex                                  m_mutex;
    std::condition_variable                     m_conditionVariable;
};


void GenerateRandomBytes(std::uint8_t* buffer, size_t length)
{
#ifdef __APPLE__
    int result = SecRandomCopyBytes(kSecRandomDefault, length, buffer);
    if (result != 0) {
        throw std::runtime_error("Error: SecRandomCopyBytes failed with error " + std::to_string(result));
    }
#elif defined(__linux__)
    int result = RAND_bytes(buffer, length);
    if (result != 1) {
        throw std::runtime_error("Error: RAND_bytes failed");
    }
#endif
}


const std::string helpMessage = R"""(
Scan a disk for bad blocks by writing and reading back data in a random order. This have several
advantages over the traditional badblocks program:
  - The random order might stress the disk more, and/or create a more realistic workload.
  - Will help detect SMR disks, as they will perform poorly when writing in a random order.
  - The data is by default unpredictable, making it impossible to compress, deduplicate, or "fake"
    the data on the disk by the firmware. If the test succeeds, you can be 100 % sure that the disk
    has the capacity it claims to have.
  - The data is (by default) unpredictable, making it suitable to use for deniable encryption without 
    spending additional time with that (e.g. you can safely do "quick format" in VeraCrypt).

The program also has other advantages, such as showing graphs at the end of the test, and being
able to resume a test that was interrupted (if --seed=SEED was used).

  cryptobadblocks [OPTION ...] DEVICE

  OPTIONS

  -h, --help
        Show this help message.
  -b, --block-size=SIZE
        Specify the block size to use. Must be a multiple of the device block size. Can be suffixed
        with k, M, G. Default is 1M. Note that the block size should be much lower than the 
        available memory as the program will allocate multiple memory buffers of this size. But the 
        block size should also not be too small, as the program will allocate memory for each block
        (unless --no-graphs and --no-summary are used).
  -c, --count=COUNT
        Specify the number of blocks to test. Default is ALL.
  -o, --overlap=PERCENT
        If larger than 0, the write operation is overlapped with reads, such that PERCENT of the
        writes are succeeded by a read operation, until all blocks have been written (at which
        point only reads are performed). Default is 0 (i.e. write the whole device first, then
        read the whole device to verify the data).
  -r, --resume
        Scan for the last block written, and resume from there. This is useful if the program was
        interrupted and you want to continue where it left off. This will not work when overlap is
        used, and you must specify the same seed or pattern as before.
  -s, --seed=SEED
        Specify the seed to use for the random number generator. If not specified, a random seed is
        used, which makes it impossible to resume the test later, and to try the exact same test
        again. To make the data unpredictable on disk, this seed must have sufficiently high entropy
        (i.e. a long, unpredictable string, similar to a secure password). This option is incompatible
        with -p.
  -p, --pattern=PATTERN
        Specify the pattern to use for writing. The pattern must be a string of hexadecimal digits,
        and is padded with zeros up the the closest larger power of 2 (e.g. 2, 4, 8, 16, 32, ...).
        This option is incompatible with -s. Default is no pattern, a random seed is used instead.
  -l, --linear
        Write and read the blocks in linear order. This is useful for testing the speed of the disk
        without stressing it too much.
  -g, --no-graphs
        Do not show graphs at the end of the test.
  -u, --no-summary
        Do not show a summary at the end of the test.

  DEVICE
        The device to test. This must be a block device, e.g. /dev/sdx or /dev/rdisk42.
)""";

std::uint64_t parseSize(const std::string& sizeStr) {
    std::uint64_t factor = 1;
    std::string number = sizeStr;
    char suffix = sizeStr.back();

    switch (suffix) {
        case 'k': case 'K': factor = 1024; number.pop_back(); break;
        case 'm': case 'M': factor = 1024 * 1024; number.pop_back(); break;
        case 'g': case 'G': factor = 1024 * 1024 * 1024; number.pop_back(); break;
        default: break;
    }
    return std::stoull(number) * factor;
}

Options parseCommandLine(int argc, char *argv[]) {
    Options opts;
    std::unordered_map<std::string, std::string> longOptions = {
        {"-b", "--block-size="}, {"-c", "--count="}, {"-o", "--overlap="},
        {"-r", "--resume"}, {"-s", "--seed="}, {"-p", "--pattern="},
        {"-g", "--no-graphs"}, {"-u", "--summary="},
        {"-h", "--help"}, {"-l", "--linear"}
    };

    int i = 1;
    for (i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "-b" || arg.find(longOptions["-b"]) == 0) {
            std::string value = (arg == "-b") ? argv[++i] : arg.substr(longOptions["-b"].size());
            opts.blockSize = parseSize(value);

        } else if (arg == "-c" || arg.find(longOptions["-c"]) == 0) {
            std::string value = (arg == "-c") ? argv[++i] : arg.substr(longOptions["-c"].size());
            std::transform(value.begin(), value.end(), value.begin(), [](char c) { return std::toupper(c); });

            if (value == "ALL") {
                opts.count = std::nullopt;
            } else {
                opts.count = std::stoul(value);
            }

        } else if (arg == "-o" || arg.find(longOptions["-o"]) == 0) {
            std::string value = (arg == "-o") ? argv[++i] : arg.substr(longOptions["-o"].size());
            opts.overlap = std::stod(value);

            if (opts.overlap < 0 || opts.overlap > 100) {
                throw std::invalid_argument("Error: --overlap must be in the range [0, 100].");
            }

        } else if (arg == "-r" || arg == longOptions["-r"]) {
            opts.resume = true;

        } else if (arg == "-s" || arg.find(longOptions["-s"]) == 0) {
            std::string value = (arg == "-s") ? argv[++i] : arg.substr(longOptions["-s"].size());
            opts.seed = value;

        } else if (arg == "-p" || arg.find(longOptions["-p"]) == 0) {
            std::string value = (arg == "-p") ? argv[++i] : arg.substr(longOptions["-p"].size());
            opts.pattern = value;

        } else if (arg == "-l" || arg == longOptions["-l"]) {
            opts.linear = true;

        } else if (arg == "-g" || arg == longOptions["-g"]) {
            opts.noGraphs = true;

        } else if (arg == "-u" || arg == longOptions["-u"]) {
            opts.summaryFile = (arg == "-u") ? argv[++i] : arg.substr(longOptions["-u"].size());

            if (opts.summaryFile.empty()) {
                throw std::invalid_argument("Error: Empty summary file name.");
            }

        } else if (arg == "-h" || arg == longOptions["-h"]) {
            std::cout << helpMessage << std::endl;
            exit(0);

        } else if (arg[0] != '-') {
            if (!opts.device.empty()) {
                throw std::invalid_argument("Error: Device already specified as '" + opts.device + 
                                            "', cannot specify another device '" + arg + "'.");
            }
            if (arg.empty()) {
                throw std::invalid_argument("Error: Empty device name.");
            }
            opts.device = arg;

        } else {
            throw std::invalid_argument("Unknown option: " + arg);
        }
    }

    if (i < argc) {
        throw std::invalid_argument("Error: Too many non-option arguments.");
    }

    if (opts.device.empty()) {
        throw std::invalid_argument("No device specified.");
    }

    if (opts.seed.has_value() && opts.pattern.has_value()) {
        throw std::invalid_argument("Error: --seed and --pattern are incompatible.");
    }

    if (opts.pattern.has_value()) {
        std::string pattern = *opts.pattern;
        if (pattern.size() == 0) {
            throw std::invalid_argument("Error: --pattern must have an even number of digits.");
        }
        for (char c : pattern) {
            if (!std::isxdigit(c)) {
                throw std::invalid_argument("Error: --pattern must be a string of hexadecimal digits.");
            }
        }

        // Pad the pattern with zeros up to the closest larger power of 2
        unsigned int smallestLargerPowerOf2 = 1;
        while (smallestLargerPowerOf2 < pattern.size()) {
            smallestLargerPowerOf2 *= 2;
        }
        if (smallestLargerPowerOf2 != pattern.size()) {
            pattern.insert(0, smallestLargerPowerOf2 - pattern.size(), '0');
        }
        opts.pattern = pattern;
    }

    if (opts.overlap > 0 && opts.resume) {
        throw std::invalid_argument("Error: --overlap and --resume are incompatible.");
    }

    if (opts.resume && !opts.seed.has_value() && !opts.pattern.has_value()) {
        throw std::invalid_argument("Error: --resume requires --seed or --pattern to be specified.");
    }

    return opts;
}


int main(int argc, char *argv[])
{
    if (argc < 2) {
        std::cerr << helpMessage << std::endl;
        return 1;
    }

    /// Parse command line arguments
    Options opts;
    try {
        opts = parseCommandLine(argc, argv);
        std::cout << "Block size: " << opts.blockSize << "\n";
        std::cout << "Count: " << (opts.count ? std::to_string(*opts.count) : "ALL") << "\n";
        std::cout << "Overlap: " << opts.overlap << "%\n";
        std::cout << "Resume: " << (opts.resume ? "Yes" : "No") << "\n";
        std::cout << "Seed: " << (opts.seed ? *opts.seed : "Random") << "\n";
        std::cout << "Pattern: " << (opts.pattern ? *opts.pattern : "None") << "\n";
        std::cout << "No graphs: " << (opts.noGraphs ? "Yes" : "No") << "\n";
        std::cout << "Summary file: " << opts.summaryFile << "\n";
        std::cout << "Device: " << opts.device << "\n";
    }
    catch (const std::invalid_argument &e) {
        std::cerr << e.what() << std::endl;
        return 1;
    }


    /// Fill in AES keys
    TAESKey iterationOrderKey = {};
    TAESKey dataKey = {};

    if (opts.seed.has_value()) {
        iterationOrderKey = GenerateKeyFromString("seed_iteration_" + *opts.seed, 0);
        dataKey = GenerateKeyFromString("seed_data_" + *opts.seed, 1);
    }
    else if (opts.pattern.has_value()) {
        iterationOrderKey = GenerateKeyFromString("pattern_iteration_" + *opts.pattern, 0);
    }
    else {
        try {
            GenerateRandomBytes(iterationOrderKey.data(), iterationOrderKey.size());
            GenerateRandomBytes(dataKey.data(), dataKey.size());
        }
        catch (const std::runtime_error& e) {
            std::cout << e.what() << std::endl;
            return 1;
        }
    }


    /// Temp encryption test, REMOVE!
    std::vector<std::uint8_t> original = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    CAESCTR aes(dataKey);
    std::vector<std::uint8_t> ciphertext(original.size());
    std::vector<std::uint8_t> plaintext(original.size());
    std::uint64_t iv = 42;
    if (!aes.Encrypt(original.data(), ciphertext.data(), original.size(), iv)) {
        std::cerr << "Error: AES encryption failed" << std::endl;
        return 1;
    }
    if (!aes.Decrypt(ciphertext.data(), plaintext.data(), ciphertext.size(), iv)) {
        std::cerr << "Error: AES decryption failed" << std::endl;
        return 1;
    }
    if (original != plaintext) {
        std::cerr << "Error: AES encryption/decryption failed" << std::endl;
        return 1;
    }


    /// CMain loop
    try {
        CMain main(opts.device);
        main.Mainloop(iterationOrderKey, dataKey, opts);
    }
    catch (const std::exception &e) {
        std::cerr << e.what() << std::endl;
        return 1;
    }


    return 0;
}
