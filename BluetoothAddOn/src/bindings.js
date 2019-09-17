var Bluetooth

if (process.env.DEBUG) {
  Bluetooth= require('./build/Debug/Bluetooth.node')
} else {
  Bluetooth= require('./build/Release/Bluetooth.node')
}

module.exports = Bluetooth