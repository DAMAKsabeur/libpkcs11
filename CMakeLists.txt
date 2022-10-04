cmake_minimum_required(VERSION 3.14)

project(pkcs11-hsm VERSION 1.0.0 LANGUAGES C)

#add_compile_options(-Wall -Wbad-function-cast -Wcast-align 
#		   -Werror-implicit-function-declaration -Wextra 
#		   -Wfloat-equal -Wformat-nonliteral -Wformat-security 
#		   -Wformat=2 -Winit-self -Wmissing-declarations 
#		   -Wmissing-format-attribute -Wmissing-include-dirs 
#		   -Wmissing-noreturn -Wmissing-prototypes -Wnested-externs 
#		   -Wpointer-arith -Wshadow -Wstrict-prototypes 
#		   -Wswitch-default -Wunsafe-loop-optimizations 
#		   -Wwrite-strings -DDEBUG -g -DPRINT_INFO)
#-Werror -Wextra
set(LIB_PKCS11_HSE_SRC
${PROJECT_SOURCE_DIR}/src/crypto.c 
${PROJECT_SOURCE_DIR}/src/general.c 
${PROJECT_SOURCE_DIR}/src/objects.c 
${PROJECT_SOURCE_DIR}/src/p11_crypto.c 
${PROJECT_SOURCE_DIR}/src/p11_general.c 
${PROJECT_SOURCE_DIR}/src/p11_object.c 
${PROJECT_SOURCE_DIR}/src/p11_session_slot.c 
${PROJECT_SOURCE_DIR}/src/sessions.c 
${PROJECT_SOURCE_DIR}/src/simclist.c
${PROJECT_SOURCE_DIR}/impl/src/nxp_slot.c 
${PROJECT_SOURCE_DIR}/impl/src/nxp_api.c
${PROJECT_SOURCE_DIR}/impl/src/aes.c
${PROJECT_SOURCE_DIR}/impl/src/md5.c
${PROJECT_SOURCE_DIR}/impl/src/pbkdf2_hmac.c
${PROJECT_SOURCE_DIR}/impl/src/sha224.c
${PROJECT_SOURCE_DIR}/impl/src/sha512.c
${PROJECT_SOURCE_DIR}/impl/src/tea.c
${PROJECT_SOURCE_DIR}/impl/src/digest.c
${PROJECT_SOURCE_DIR}/impl/src/rc4.c
${PROJECT_SOURCE_DIR}/impl/src/sha256.c
${PROJECT_SOURCE_DIR}/impl/src/sha.c
${PROJECT_SOURCE_DIR}/impl/src/hmac.c
${PROJECT_SOURCE_DIR}/impl/src/sha1.c
${PROJECT_SOURCE_DIR}/impl/src/sha384.c
${PROJECT_SOURCE_DIR}/impl/src/tdes.c

)

SET(LIB_PKCS11_HSE_HEADER_FILES 
${PROJECT_SOURCE_DIR}/include/crypto.h
${PROJECT_SOURCE_DIR}/include/general.h
${PROJECT_SOURCE_DIR}/include/objects.h
${PROJECT_SOURCE_DIR}/include/sessions.h
${PROJECT_SOURCE_DIR}/include/simclist.h
${PROJECT_SOURCE_DIR}/public/cryptoki.h
${PROJECT_SOURCE_DIR}/public/pkcs11f.h
${PROJECT_SOURCE_DIR}/public/pkcs11.h
${PROJECT_SOURCE_DIR}/public/pkcs11t.h
${PROJECT_SOURCE_DIR}/impl/include/nxp_api_types.h
${PROJECT_SOURCE_DIR}/impl/include/nxp_api.h
${PROJECT_SOURCE_DIR}/impl/include/nxp_mp.h
${PROJECT_SOURCE_DIR}/impl/include/nxp_slot.h
${PROJECT_SOURCE_DIR}/impl/include/aes.h
${PROJECT_SOURCE_DIR}/impl/include/common.h
${PROJECT_SOURCE_DIR}/impl/include/digest.h
${PROJECT_SOURCE_DIR}/impl/include/hmac.h
${PROJECT_SOURCE_DIR}/impl/include/md5.h
${PROJECT_SOURCE_DIR}/impl/include/pbkdf2_hmac.h
${PROJECT_SOURCE_DIR}/impl/include/rc4.h
${PROJECT_SOURCE_DIR}/impl/include/sha1.h
${PROJECT_SOURCE_DIR}/impl/include/sha224.h
${PROJECT_SOURCE_DIR}/impl/include/sha256.h
${PROJECT_SOURCE_DIR}/impl/include/sha384.h
${PROJECT_SOURCE_DIR}/impl/include/sha512.h
${PROJECT_SOURCE_DIR}/impl/include/sha.h
${PROJECT_SOURCE_DIR}/impl/include/ssh.h
${PROJECT_SOURCE_DIR}/impl/include/tdes.h
${PROJECT_SOURCE_DIR}/impl/include/tea.h
)

SET(PUBLIC_LIB_PKCS11_HSE_HEADERS 
${PROJECT_SOURCE_DIR}/public/cryptoki.h
${PROJECT_SOURCE_DIR}/public/pkcs11f.h
${PROJECT_SOURCE_DIR}/public/pkcs11.h
${PROJECT_SOURCE_DIR}/public/pkcs11t.h
)
 
include_directories(
${PROJECT_SOURCE_DIR}/include
${PROJECT_SOURCE_DIR}/public
${PROJECT_SOURCE_DIR}/impl/include
)
   

#add_subdirectory(app)

MESSAGE ( ${LIB_PKCS11_HSE_SRC})

add_library (pkcs11-hsm SHARED ${LIB_PKCS11_HSE_SRC} ${LIB_PKCS11_HSE_HEADER_FILES})
#~ target_link_libraries (nxp-hse LINK_PUBLIC)

 
set_target_properties(pkcs11-hsm PROPERTIES PUBLIC_HEADER "${PUBLIC_LIB_PKCS11_HSE_HEADERS}")

install (TARGETS pkcs11-hsm DESTINATION lib PUBLIC_HEADER DESTINATION include)

