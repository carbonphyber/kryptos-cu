// #include <fstream>
#include <iostream>
#include <thrust/device_vector.h>
#include <thrust/execution_policy.h>
#include <thrust/functional.h>
#include <thrust/host_vector.h>
#include <thrust/transform.h>
#include <vector>

#define K1_CIPHERTEXT "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJYQTQUXQBQVYUVLLTREVJYQTMKYRDMFD"
#define K1_PLAINTEXT "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION"
#define K1_KEY "PALIMPSEST"
#define K1_ALPHABET "KRYPTOSABCDEFGHIJLMNQUVWXZ"
#define NUM_OF_LETTERS 26

// quagmire_three_decrypt
template <typename T, typename U>
struct quagmire_three_decrypt : public thrust::binary_function<T,T,U>
{
  __host__ __device__
  U operator()(T the_cipher_index, T the_key_index)
  {
    unsigned int cipher_char_offset = 0;
    unsigned int key_offset = 0;
    for (int i = 0; i < NUM_OF_LETTERS; i++) {
      if (i == the_cipher_index) cipher_char_offset = i;
      if (i == the_key_index) key_offset = i;
    }
    int alphabet_offset = cipher_char_offset
      - key_offset
      + (cipher_char_offset >= key_offset ? 0 : NUM_OF_LETTERS);
    return K1_ALPHABET[alphabet_offset];
  }
};

// calc_index_of_coincidence
__host__ // __device__
double calc_index_of_coincidence(const thrust::device_vector<unsigned char> &text) {
  int length = text.size();
  int sum = 0;
  int letter_counts[NUM_OF_LETTERS] = {
    0, 0, 0, 0, 0,
    0, 0, 0, 0, 0,
    0, 0, 0, 0, 0,
    0, 0, 0, 0, 0,
    0, 0, 0, 0, 0,
    0,
  };
  for(int i = 0; i < length; i++) {
    letter_counts[text[i] - 'A'] += 1;
  }
  for(int i = 0; i < NUM_OF_LETTERS; i++) {
    sum += letter_counts[i] > 0
      ? (letter_counts[i] * (letter_counts[i] - 1))
      : 0;
  }
  double ioc = length <= 1
    ? 0.0f
    : sum / (double)((length) * (length - 1));
  return ioc;
}

__host__ // __device__
unsigned char letter_index_to_char(unsigned int the_letter_index) {
  return 'A' + the_letter_index;
}

// main
int main(int argc, char **argv) {
  std::cout << "K1_CIPHERTEXT: " << K1_CIPHERTEXT << std::endl;
  std::cout << "K1_PLAINTEXT: " << K1_PLAINTEXT << std::endl;
  std::cout << "K1_KEY: " << K1_KEY << std::endl;
  std::cout << "K1_ALPHABET: " << K1_ALPHABET << std::endl;

  int k1_len = strlen(K1_CIPHERTEXT);

  thrust::host_vector<unsigned int> h_k1(k1_len);
  thrust::host_vector<unsigned int> h_k1_ciphertext(k1_len);
  for(int i = 0; i < k1_len; i++) {
    int this_cipher_letter = K1_CIPHERTEXT[i];
    h_k1_ciphertext[i] = (unsigned char)this_cipher_letter;
    int this_alphabet_index = 0;
    for (int j = 0; j < NUM_OF_LETTERS; j++) {
      if (this_cipher_letter == K1_ALPHABET[j]) this_alphabet_index = j;
    }
    h_k1[i] = this_alphabet_index;
  }

  // print out IoC value
  double k1_ciphertext_ioc = calc_index_of_coincidence(h_k1_ciphertext);
  std::cout << "IoC: " << k1_ciphertext_ioc << std::endl << std::endl;

  // print out K1 indexes
  std::cout << "k1: ";
  thrust::copy_n(h_k1.begin(), k1_len, std::ostream_iterator<unsigned int>(std::cout, " "));
  std::cout << std::endl << std::endl;

  // repeat the key for the length of the k1 string
  thrust::host_vector<unsigned int> h_k1_key(k1_len);
  int k1_key_len = strlen(K1_KEY);
  for(int i = 0; i < k1_len; i++) {
    int this_key_letter = K1_KEY[i % k1_key_len];
    int this_alphabet_index = 0;
    for (int j = 0; j < NUM_OF_LETTERS; j++) {
      if (this_key_letter == K1_ALPHABET[j]) this_alphabet_index = j;
    }
    h_k1_key[i] = this_alphabet_index;
  }
  // thrust::copy_n(h_k1_key.begin(), k1_len, std::ostream_iterator<unsigned int>(std::cout, ""));
  std::cout << "key: ";
  thrust::copy_n(h_k1_key.begin(), k1_len, std::ostream_iterator<unsigned int>(std::cout, " "));
  std::cout << std::endl << std::endl;

  // transform k1 ciphertext indexes and k1 key indexes into k1 plaintext indexes
  thrust::host_vector<unsigned char> h_k1_decrypted(k1_len);
  thrust::transform(thrust::host, h_k1.begin(), h_k1.end(), h_k1_key.begin(), h_k1_decrypted.begin(), quagmire_three_decrypt<unsigned int, unsigned char>());
  std::cout << "h_k1_decrypted: ";
  thrust::copy_n(h_k1_decrypted.begin(), k1_len, std::ostream_iterator<unsigned char>(std::cout, " "));
  std::cout << std::endl << std::endl;

  // print out IoC value
  double k1_plaintext_ioc = calc_index_of_coincidence(h_k1_decrypted);
  std::cout << "Decrypted IoC: " << k1_plaintext_ioc << std::endl << std::endl;

  return EXIT_SUCCESS;
}
