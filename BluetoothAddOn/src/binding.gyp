{
  "targets": [{
    "target_name": "Bluetooth",
    "include_dirs" : [
      "src",
      "<!(node -e \"require('nan')\")"
    ],
    "sources": [
      "index.cc",
      "BluetoothServer.cc"
    ]
  }]
}