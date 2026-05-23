#pragma once
#include <string>
#include <type_traits>
// this is a HEAVILY modified version of skCrypt
// made by ellii / kidthegoatedgoa
// original repo: https://github.com/skadro-official/skCrypter
namespace strcrypt {
	template <typename T> using clean_type = std::remove_const_t<std::remove_reference_t<T>>;

	template <std::size_t Size, char Key1, char Key2, typename T> class strcrypt {
	public:
		constexpr explicit strcrypt(const T* data) {
			crypt(data);
		}

		T* get() noexcept {
			return _storage;
		}

		constexpr std::size_t size() const noexcept {
			return Size;
		}

		constexpr char key() const noexcept {
			return Key1;
		}

		T* encrypt() {
			if (!is_encrypted)
				do_crypt(_storage);
			return _storage;
		}

		T* decrypt() {
			if (is_encrypted)
				do_crypt(_storage);
			return _storage;
		}

		bool isEncrypted() const noexcept {
			return is_encrypted;
		}

		void clear() noexcept {
			for (std::size_t i = 0; i < Size; ++i) {
				_storage[i] = 0;
			}
		}

		operator T* () {
			return decrypt();
		}

	private:
		constexpr void crypt(const T* data) {
			for (std::size_t i = 0; i < Size; ++i) {
				_storage[i] = data[i] ^ compute_xor(i);
			}
			is_encrypted = true;
		}

		void do_crypt(T* data) noexcept {
			for (std::size_t i = 0; i < Size; ++i) {
				data[i] ^= compute_xor(i);
			}
			is_encrypted = !is_encrypted;
		}

		constexpr uint8_t compute_xor(std::size_t i) const noexcept {
			return static_cast<uint8_t>(Key1 + ((i * Key2) & 0xFF));
		}

		T _storage[Size]{};
		bool is_encrypted = false;
	};

} // namespace strcrypt

template <typename T, uint8_t Key1, uint8_t Key2>
class intcrypt {
public:
	constexpr explicit intcrypt(T value)
		: encrypted(crypt(value)) {
	}

	constexpr T decrypt() const noexcept {
		return crypt(encrypted);
	}

	constexpr T encrypted_value() const noexcept {
		return encrypted;
	}

private:
	static constexpr T crypt(T value) noexcept {
		using U = std::make_unsigned_t<T>;

		U v = static_cast<U>(value);

		for (size_t i = 0; i < sizeof(T); ++i) {
			uint8_t byte =
				static_cast<uint8_t>((v >> (i * 8)) & 0xFF);

			byte ^= static_cast<uint8_t>(
				Key1 + ((i * Key2) & 0xFF));

			v &= ~(static_cast<U>(0xFF) << (i * 8));
			v |= (static_cast<U>(byte) << (i * 8));
		}

		return static_cast<T>(v);
	}

	T encrypted;
};

constexpr uint64_t ct_hash(const char* s, uint64_t h = 1469598103934665603ULL) {
	return *s ? ct_hash(s + 1, (h ^ *s) * 1099511628211ULL) : h;
}

__forceinline constexpr uint32_t constexpr_hash(const char* str, size_t len) {
	uint32_t hash = 2166136261u; // fnv1a
	for (size_t i = 0; i < len; ++i)
		hash = (hash ^ str[i]) * 16777619u;
	return hash;
}

static constexpr uintptr_t security_key = static_cast<uintptr_t>(ct_hash(__DATE__ __TIME__ __FILE__)) ^ (uintptr_t(__LINE__) << 32) ^ 0xB16B00B5; // i love cats

#define SALT_1 (constexpr_hash(__TIME__, 8) & 0xFF)
#define SALT_2 (constexpr_hash(__DATE__, 11) & 0xFF)

__forceinline constexpr uint8_t mix_key(uint8_t k, uint32_t s) {
	k ^= (k >> 3) + (s & 0xFF);
	k += (s >> 8) & 0xFF;
	k ^= ((k << 5) | 0xA3);
	return k;
}

#define RANDOM_KEY1 mix_key(security_key, SALT_1)
#define RANDOM_KEY2 mix_key(security_key + 0x67, SALT_2)
#define RANDOM_KEY3 mix_key(security_key ^ 4, SALT_1 ^ SALT_2)
#define RANDOM_KEY4 mix_key(security_key + RANDOM_KEY1, SALT_2 + 0x33)

#define encrypt_key_str(str, key1, key2) \
[]() { \
    constexpr static auto crypted = \
    strcrypt::strcrypt<sizeof(str) / sizeof(str[0]), key1, key2, strcrypt::clean_type<decltype(str[0])>>(str); \
    return crypted; \
}()

#define encrypt(str) encrypt_key_str(str, RANDOM_KEY3, RANDOM_KEY4)
#define encrypt2(str) encrypt_key_str(str, RANDOM_KEY1, RANDOM_KEY2)
#define encrypt_int(str) encrypt_key_int(str, RANDOM_KEY1, RANDOM_KEY2)

#define _(str) ([] { return std::string(encrypt2(str).decrypt()); })() // returns std::string
#define _c(str) ([] { return encrypt(str).decrypt(); })() // returns char*

#define encrypt_int(num) \
[]() { \
    constexpr static auto crypted = \
        intcrypt<decltype(num), RANDOM_KEY1, RANDOM_KEY2>(num); \
    return crypted; \
}()
#define _int(num) ([] { return encrypt_int(num).decrypt(); })()
