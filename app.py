import streamlit as st
import codecs
import base64
import urllib.parse
import hashlib
import random, string
def encode_rot13(s):
    return codecs.encode(s, 'rot13')

def decode_rot13(s):
    return codecs.decode(s, 'rot13')

def encode_base64(s):
    return base64.b64encode(s.encode("ascii")).decode("ascii") 

def decode_base64(s):
    return base64.b64decode(s.encode("ascii")).decode("ascii") 

def encode_hex(s):
    return s.encode("utf-8").hex()
def decode_hex(s):
    return bytearray.fromhex(s).decode()
def encode_url(s):
    return urllib.parse.quote(s)

def decode_url(s):
    return urllib.parse.unquote(s)

def encode_md5(s):
    return hashlib.md5(s.encode('utf-8')).hexdigest()

def encode_sha1(s):
    return hashlib.sha1(s.encode('utf-8')).hexdigest()

def encode_sha256(s):
    return hashlib.sha256(s.encode('utf-8')).hexdigest()

def encode_sha512(s):
    return hashlib.sha512(s.encode('utf-8')).hexdigest()

# Password Generator 

def password(length,num=False,strength='Weak'):
    lower = string.ascii_lowercase
    upper = string.ascii_uppercase
    letter = lower + upper
    dig = string.digits
    punct = string.punctuation
    pwd = ''
    if strength == 'Weak':
        if num:
            length -= 2
            for i in range(2):
                pwd += random.choice(dig)
        for i in range(length):
            pwd += random.choice(lower)

    elif strength == 'Strong':
        if num:
            length -=2
            for i in range(2):
                pwd += random.choice(dig)
        for i in range(length):
            pwd += random.choice(letter)
    elif strength == 'Extreame':
        ran = random.randint(2,4)
        if num:
            length -= ran
            for i in range(ran):
                pwd += random.choice(dig)
        length -= ran
        for i in range(ran):
            pwd += random.choice(punct)
        for i in range(length):
            pwd += random.choice(letter)
    pwd = list(pwd)
    random.shuffle(pwd)
    return ''.join(pwd)


st.set_option('deprecation.showfileUploaderEncoding', False)


def encode_decode():

    st.subheader("Encoder")
    text1 = st.text_input("Enter the text you need to decode")
    typ1 = st.selectbox('Encoding type',['ROT13','base64','hex','url',
    'md5','sha1','sha256','sha512'])
    if text1 != "":
        if typ1 == 'ROT13':
            st.success(encode_rot13(text1))
        elif typ1 == 'base64':
            st.success(encode_base64(text1))
        elif typ1 == 'url':
            st.success(encode_url(text1))
        elif typ1 == 'md5':
            st.success(encode_md5(text1))
        elif typ1 == 'sha1':
            st.success(encode_sha1(text1))
        elif typ1 == 'sha256':
            st.success(encode_sha256(text1))
        elif typ1 == 'sha512':
            st.text_area("SHA512 Encoded",encode_sha512(text1))
        elif typ1 == 'hex':
            st.text_area("Hex Encoded",encode_hex(text1))

    st.subheader("Decoder")
    text2 = st.text_area("Enter the text you need to decode")
    typ = st.selectbox('Decoding type',['ROT13','base64','hex','url'])
    if text2 != "":
        if typ == 'ROT13':
            try:
                st.success(decode_rot13(text2))
            except ValueError:
                st.error('Please enter ROT13 encoded text')
        elif typ == 'base64':
            try:
                st.success(decode_base64(text2))
            except ValueError:
                st.error('Please enter base64 encoded text')
        elif typ == 'url':
            try:
                st.success(decode_url(text2))
            except ValueError:
                st.error('Please enter url encoded text')
        elif typ == 'hex':
            try:
                st.success(decode_hex(text2))
            except ValueError:
                st.error('Please enter hex encoded text')

def pass_gen():
    st.header("Password Generator")
    leng = st.slider('Password length', min_value=8, max_value=32)
    num = st.checkbox('Add numbers to your password')
    typ = st.selectbox('Password strength',['Weak','Strong','Extream'])
    if st.button("Generate Password"):
        pswd = password(leng,num,typ)
        st.success(pswd)
    if st.button("Source Code"):
        st.write('''
        > Code

        ```
        def password(length,num=False,strength='weak'):
            lower = string.ascii_lowercase
            upper = string.ascii_uppercase
            letter = lower + upper
            dig = string.digits
            punct = string.punctuation
            pwd = ''
            if strength == 'weak':
                if num:
                    length -= 2
                    for i in range(2):
                        pwd += random.choice(dig)
                for i in range(length):
                    pwd += random.choice(lower)

            elif strength == 'strong':
                if num:
                    length -=2
                    for i in range(2):
                        pwd += random.choice(dig)
                for i in range(length):
                    pwd += random.choice(letter)
            elif strength == 'very':
                ran = random.randint(2,4)
                if num:
                    length -= ran
                    for i in range(ran):
                        pwd += random.choice(dig)
                length -= ran
                for i in range(ran):
                    pwd += random.choice(punct)
                for i in range(length):
                    pwd += random.choice(letter)
            pwd = list(pwd)
            random.shuffle(pwd)
            return ''.join(pwd)
        ```
        ''')


def about():
    st.subheader("> **Cryptography**")
    st.write(
        '''
        A cryptographic hash function (CHF) is a mathematical algorithm that maps 
        data of arbitrary size (often called the "message").

---
***ROT13***

ROT13 ("rotate by 13 places", sometimes hyphenated ROT-13) is a simple letter 
substitution cipher that replaces a letter with the 13th letter after it in the alphabet. 
ROT13 is a special case of the Caesar cipher which was developed in ancient Rome.
        ''')
    st.image('img/ROT13.png', caption='ROT13',width=500)
    st.write(
        '''
---
***Base64***

Base64 is a group of binary-to-text encoding schemes that represent binary data 
(more specifically a sequence of 8-bit bytes) in an ASCII string format by 
translating it into a radix-64 representation. 
    ''')
    st.image('img/base.png', caption='base64')
    st.write(
        '''
---
***URL***

URL encoding stands for encoding certain characters in a URL 
by replacing them with one or more character triplets that 
consist of the percent character "%" followed by two hexadecimal 
digits. The two hexadecimal digits of the triplet(s) represent 
the numeric value of the replaced character.
    ''')
    st.image('img/url.png', caption='url',width=180)
    st.subheader("> **One Way Cryptography**")
    st.write(
        '''
---
***MD5***

The MD5 message-digest algorithm is a widely used hash 
function producing a 128-bit hash value. Although MD5 
was initially designed to be used as a cryptographic 
hash function, it has been found to suffer from extensive vulnerabilities.
    ''')
    st.write(
        '''
---
***SHA1***

SHA-1 (Secure Hash Algorithm 1) is a cryptographic hash function 
which takes an input and produces a 160-bit (20-byte) hash value 
known as a message digest – typically rendered as a hexadecimal 
number, 40 digits long. It was designed by the United States National Security Agency
    ''')
    st.write(
        '''
---
***SHA-256***

SHA-256 is one of the successor hash functions to SHA-1 
(collectively referred to as SHA-2), and is one of the strongest hash 
functions available. SHA-256 is not much more complex to code than SHA-1, 
and has not yet been compromised in any way. 
    ''')
    st.write(
        '''
---
***SHA-256***

 SHA-512 is more difficult to implement in JavaScript than SHA-256, as it is based on 64-bit
 (unsigned) integers, which are not natively supported in JavaScript (in which all numbers are
 IEEE 754 64-bit floating-point numbers). A 'Long' library here provides UInt64-style support. 
    ''')
    st.markdown("""<a href="http://www.gaganv.me" target="_blank" style="text-decoration: none; font-weight: bold; font-size: 20px; color: #4CA1AF;">Gagan Verma</a>""",unsafe_allow_html=True)
    st.markdown("""<a href="https://www.hackthebox.eu/" target="_blank"><img src="http://www.hackthebox.eu/badge/image/346677" alt="Hack The Box"></a>""", unsafe_allow_html=True)
    st.markdown("Contributor : ")
    st.markdown("""<a href="https://github.com/souravsingpardeshi" target="_blank" style="text-decoration: none; font-weight: bold; font-size: 14px; color: #4CA1AF;">Souravsing Pardeshi</a>""",unsafe_allow_html=True)
def main():
    # st.write("All in one tool")
    activities = ["Home", "Encode Decode", "Password Generator", "About"]
    choice = st.sidebar.selectbox("Navbar", activities)
    hide_streamlit_style = """
        <title> Yato </title>
        <style>
        .fullScreenFrame > div {display: flex; justify-content: center;}
        footer {visibility: hidden;}
        .sidebar .sidebar-content {background-image: linear-gradient(180deg,#4CA1AF,#2c3e50);}
        .btn-outline-secondary {
        border-color: #09ab3b85;
        color: #f9f9f9;
        }
        </style>
        """
    st.markdown(hide_streamlit_style, unsafe_allow_html=True) 

    if choice == "Home":
        st.markdown("""        
        <style>
        body{color: #ffffff; background-color: #000;} 
        """,unsafe_allow_html=True)
        st.header("3NCRYPTI0N")
        st.subheader(":smile: Welcome ^^")
        st.image("img/ENCRYPTION.gif")
        st.write('''
        ---
        One place for Decoding, Encoding and Password Generator 

        ''')
    elif choice == "Encode Decode":
        encode_decode()
    elif choice == "Password Generator":
        pass_gen()
    elif choice == "About":
        about()

        

if __name__ == '__main__':
    main()
