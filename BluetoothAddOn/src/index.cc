#include <nan.h>
#include "BluetoothServer.h"

NAN_MODULE_INIT(InitModule) {
  BluetoothServer::Init(target);
}

NODE_MODULE(Bluetooth, InitModule);