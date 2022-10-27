#!/bin/bash

accounts=$USERS

for account in "${accounts[@]}"; do
    creds=(${account//:/ })
    user=${creds[0]}
    pass=${creds[1]}

    echo "Creating user: $user"
    useradd -mk /etc/skel/ "$user"
    usermod --shell "/bin/bash" "$user"
    echo "$user:$pass" | chpasswd
done