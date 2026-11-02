// K109 containment probe transport: boots the cloud image with ONE writable
// virtio-fs share (tag "share") and captures the console. The guest battery
// runs via cloud-init and powers off; no vsock, no network device.
import Foundation
import Virtualization
import Darwin

func event(_ value: [String: Any]) {
    let data = try! JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
    FileHandle.standardOutput.write(data + Data([10]))
}

let arguments = CommandLine.arguments.dropFirst()
guard Array(arguments).count == 5 else {
    event(["event": "usage", "usage": "vzshare DISK SEED NVRAM CONSOLE SHARE_DIR"])
    exit(2)
}
let paths = Array(arguments)
let shareURL = URL(fileURLWithPath: paths[4])

let config = VZVirtualMachineConfiguration()
config.cpuCount = 2
config.memorySize = 2 * 1024 * 1024 * 1024
let boot = VZEFIBootLoader()
boot.variableStore = try VZEFIVariableStore(creatingVariableStoreAt: URL(fileURLWithPath: paths[2]))
config.bootLoader = boot
config.storageDevices = try paths[0...1].enumerated().map { index, path in
    VZVirtioBlockDeviceConfiguration(attachment: try VZDiskImageStorageDeviceAttachment(
        url: URL(fileURLWithPath: path), readOnly: index == 1))
}
config.entropyDevices = [VZVirtioEntropyDeviceConfiguration()]
config.socketDevices = [VZVirtioSocketDeviceConfiguration()]
let console = VZVirtioConsoleDeviceSerialPortConfiguration()
let output = open(paths[3], O_WRONLY | O_CREAT | O_EXCL, 0o600)
guard output >= 0 else { event(["event": "error", "error": "console"]); exit(125) }
console.attachment = VZFileHandleSerialPortAttachment(
    fileHandleForReading: nil,
    fileHandleForWriting: FileHandle(fileDescriptor: output, closeOnDealloc: true))
config.serialPorts = [console]
let directory = VZVirtioFileSystemDeviceConfiguration(tag: "share")
directory.share = VZSingleDirectoryShare(
    directory: VZSharedDirectory(url: shareURL, readOnly: false))
config.directorySharingDevices = [directory]
try config.validate()
let vm = VZVirtualMachine(configuration: config)

final class Delegate: NSObject, VZVirtualMachineDelegate {
    func guestDidStop(_ virtualMachine: VZVirtualMachine) { event(["event": "guest_stopped"]); exit(0) }
    func virtualMachine(_ virtualMachine: VZVirtualMachine, didStopWithError error: Error) {
        event(["event": "error", "error": String(describing: error)]); exit(125)
    }
}
let delegate = Delegate()
vm.delegate = delegate
vm.start { result in
    switch result {
    case .failure(let error): event(["event": "error", "error": String(describing: error)]); exit(125)
    case .success: event(["event": "booted"])
    }
}
withExtendedLifetime(delegate) { RunLoop.main.run() }
