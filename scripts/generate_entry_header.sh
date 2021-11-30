#!/bin/bash

if [[ ! -d "src/libwifi" ]]; then
    echo "[!] You must run this script from the project directory root"
    exit 1
fi

rm src/libwifi.h
touch src/libwifi.h

# Generate Header
cat <<EOF > src/libwifi.h
#ifndef LIBWIFI_H
#define LIBWIFI_H

#ifdef __cplusplus
extern "C" {
#endif

$(find src -type f -name '*.h' -printf '%P\n' | sed '/libwifi.h/d' | sort | awk '{print "#include \"" $0 "\""}')

#ifdef __cplusplus
}
#endif

#endif /* LIBWIFI_H */
EOF

echo "[!] Generated libwifi entry header!"

exit 0
