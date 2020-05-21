import requests
import hashlib
import sys


def request_api_data(query_char):
  # make request to pwnedpassword service
  url = 'https://api.pwnedpasswords.com/range/' + query_char
  res = requests.get(url)
  if res.status_code != 200:
    raise RuntimeError(f'Error fetching: {res.status_code}, check the api and try again')
  return res

def get_password_leaks_count(hashes, hash_to_check):
    # check if the tail matches with any of the returned results
    # if so, return the count of pawned password
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def pwned_api_check(password):
  # convert password input into SHA1 hash
  # split SHA1 hash into the first five characters and the tail
  # check the first five SHA1 characters, return all matching results
  sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
  first5_char, tail = sha1password[:5], sha1password[5:]
  response = request_api_data(first5_char)
  return get_password_leaks_count(response, tail)


def main(args):
    # allow multiple password inputs
    # check how many times each password have been pawned
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'{password} was found {count} times... you should probably change your password')
        else:
            print(f'{password} was not found. Congrats!')
    return 'done'


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
