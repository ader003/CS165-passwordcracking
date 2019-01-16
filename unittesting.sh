#!/bin/bash
# md5-crypt for GNU and Bash
# By Vidar 'koala_man' Holen

b64="./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

stringToNumber() { 
    expression=0
    for((i=0; i<${#1}; i++))
    do
        expression=$(printf '(%s)*256+%d' "$expression" "'${1:$i:1}")
    done
    bc <<< "$expression"
}

# Turn some string into a \xd4\x1d hex string
stringToHex() { 
    for((i=0; i<${#1}; i++))
    do
        printf '\\x%x' "'${1:i:1}"
    done
}

# Turn stdin into a \xd4\x1d style md5 hash
md5hex() { 
    sum=$(md5sum) 
    read sum rest <<< "$sum" # remove trailing dash
    hex=$(sed 's/../\\x&/g' <<< "$sum")
    echo "$hex"
}

# Turn an integer into a crypt base64 string with n characters
intToBase64() { 
    number=$1
    n=$2
    for((j=0; j<n; j++))
    do
        digit=$(bc <<< "$number % 64")
        number=$(bc <<< "$number / 64")
        echo -n "${b64:digit:1}"
    done
}

base64Index() { 
    for((i=0; i<64; i++))
    do
        if [[ ${b64:i:1} == $1 ]]
        then
            echo $i
            exit 0
        fi
    done
    exit 1
}

# From hex string $1, get the bytes indexed by $2, $3 ..
getBytes() { 
    num=$1
    shift
    for i
    do
        echo -n "${num:$((i*4)):4}"
    done
}

hexToInt() { 
    {
    echo 'ibase=16;'
    tr a-f A-F <<< "$1" | sed -e 's/\\x//g'
    } | bc
}

base64EncodeBytes() {
    n=$1
    shift 
    bytes=$(getBytes "$@")
    int=$(hexToInt "$bytes")
    intToBase64 "$int" "$n"
}

doHash() { 
    password="$1"
    passwordLength=$(printf "$password" | wc -c)
    salt="$2"
    magic="$3"
    [[ -z $magic ]] && magic='$1$'

    salt=${salt#'$1$'}
    salt=${salt:0:32} # 8 first bytes

    intermediate=$(
    {
        # Start intermediate result
        printf "$password$magic$salt" 

        # compute a separate md5 sum
        alternate=$(printf "$password$salt$password" | md5hex) 

        # Add one byte from alternate for each character in the password. Wtf?
        while printf "$alternate" 2> /dev/null
        do
          true
        done | head -c "$passwordLength"

        # For every 1 bit in the key length, add a 0.
        # Otherwise add the first char of the key. WTFFFFF?!
        for ((i=$passwordLength; i != 0; i>>=1)) 
        do
            if (( i & 1 ))
            then
                printf '\x00' 
            else 
                printf "$password" | head -c 1
            fi
        done

    } | md5hex
    )

    for((i=0; i<1000; i++))
    do
        intermediate=$({
            (( i & 1 )) && printf "$password" || printf "$intermediate"
            (( i % 3 )) && printf "$salt"
            (( i % 7 )) && printf "$password"
            (( i & 1 )) && printf "$intermediate" || printf "$password"
        } | md5hex)
    done

    # Rearrange the bytes and crypt-base64 encode them
    encoded=$(base64EncodeBytes 22 "$intermediate" 11  4 10 5  3 9 15  2 8 14  1 7 13  0 6 12)

    printf "%s$salt\$%s\n" "$magic" "$encoded" 

}


if [[ $# < 1 ]] 
then
    echo "Usage: $0 password [salt]" >&2 
    exit 1
fi

password=$(stringToHex "$1")
salt=$(stringToHex "$2")
[[ -z $salt ]] && salt=$(tr -cd 'a-zA-Z0-9' < /dev/urandom | head -c 8) 

doHash "$password" "$salt" '$1$'

