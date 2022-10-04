include_directories(${PROJECT_SOURCE_DIR}/public
)

add_executable (gen_test gen_test.c)
target_link_libraries(gen_test LINK_PUBLIC pkcs11-hsm)
install (TARGETS gen_test DESTINATION bin)


add_executable (pkcs11_app pkcs11_app.c)
target_link_libraries(pkcs11_app LINK_PUBLIC pkcs11-hsm)
install (TARGETS pkcs11_app DESTINATION bin)

add_executable (sign_digest_update_final sign_digest_update_final.c)
target_link_libraries(sign_digest_update_final LINK_PUBLIC pkcs11-hsm)
install (TARGETS sign_digest_update_final DESTINATION bin)

add_executable (thread_test thread_test.c)
target_link_libraries(thread_test LINK_PUBLIC pkcs11-hsm)
install (TARGETS thread_test DESTINATION bin)