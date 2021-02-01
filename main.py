import requests
import hashlib
import sys


def requestAPI(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)

    if res.status_code != 200:
        raise RuntimeError(f'Error getting data: {res.status_code}, check api and try again')
    return res


def get_pass_leaks_count(hashes, hash2check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash2check:
            return count
    return 0


def pwned_api_check(password):
    # Check password if it exists in API response
    sha1pass = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1pass[:5], sha1pass[5:]
    response = requestAPI(first5_char)
    # print(response.text)  #<< This is something you can take comment off to see all hashes being guessed
    return get_pass_leaks_count(response, tail)


def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'{password} was found {count} times... it may be a good idea to change the password')
        else:
            print(f'{password} was not found! Password is good to go!')


if __name__ == '__main__':
    main(sys.argv[1:])
