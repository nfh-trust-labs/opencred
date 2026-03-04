{
  "targets": [
    {
      "target_name": "macos-keychain",
      "conditions": [["OS=='mac'", {
        "sources": ["macos/macos-keychain.mm"],
        "include_dirs": ["<!@(node -p \"require('node-addon-api').include\")"],
        "cflags!": ["-fno-exceptions"],
        "xcode_settings": {
          "OTHER_LDFLAGS": ["-framework Security", "-framework CoreFoundation"],
          "CLANG_ENABLE_OBJC_ARC": "YES",
          "GCC_ENABLE_CPP_EXCEPTIONS": "YES"
        },
        "defines": ["NAPI_DISABLE_CPP_EXCEPTIONS"]
      }]]
    },
    {
      "target_name": "windows-cng",
      "conditions": [["OS=='win'", {
        "sources": ["windows/windows-cng.cpp"],
        "include_dirs": ["<!@(node -p \"require('node-addon-api').include\")"],
        "libraries": ["-lncrypt", "-lcrypt32"],
        "defines": ["NAPI_DISABLE_CPP_EXCEPTIONS"]
      }]]
    }
  ]
}
