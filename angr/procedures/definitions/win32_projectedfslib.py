# pylint:disable=line-too-long
import logging

from ...sim_type import SimTypeFunction,     SimTypeShort, SimTypeInt, SimTypeLong, SimTypeLongLong, SimTypeDouble, SimTypeFloat,     SimTypePointer,     SimTypeChar,     SimStruct,     SimTypeFixedSizeArray,     SimTypeBottom,     SimUnion,     SimTypeBool
from ...calling_conventions import SimCCStdcall, SimCCMicrosoftAMD64
from .. import SIM_PROCEDURES as P
from . import SimLibrary


_l = logging.getLogger(name=__name__)


lib = SimLibrary()
lib.set_default_cc('X86', SimCCStdcall)
lib.set_default_cc('AMD64', SimCCMicrosoftAMD64)
lib.set_library_names("projectedfslib.dll")
prototypes = \
    {
        # 
        'PrjStartVirtualizing': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimStruct({"StartDirectoryEnumerationCallback": SimTypePointer(SimTypeFunction([SimTypePointer(SimStruct({"Size": SimTypeInt(signed=False, label="UInt32"), "Flags": SimTypeInt(signed=False, label="PRJ_CALLBACK_DATA_FLAGS"), "NamespaceVirtualizationContext": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "CommandId": SimTypeInt(signed=True, label="Int32"), "FileId": SimTypeBottom(label="Guid"), "DataStreamId": SimTypeBottom(label="Guid"), "FilePathName": SimTypePointer(SimTypeChar(label="Char"), offset=0), "VersionInfo": SimTypePointer(SimStruct({"ProviderID": SimTypeFixedSizeArray(SimTypeChar(label="Byte"), 128), "ContentID": SimTypeFixedSizeArray(SimTypeChar(label="Byte"), 128)}, name="PRJ_PLACEHOLDER_VERSION_INFO", pack=False, align=None), offset=0), "TriggeringProcessId": SimTypeInt(signed=False, label="UInt32"), "TriggeringProcessImageFileName": SimTypePointer(SimTypeChar(label="Char"), offset=0), "InstanceContext": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="PRJ_CALLBACK_DATA", pack=False, align=None), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["callbackData", "enumerationId"]), offset=0), "EndDirectoryEnumerationCallback": SimTypePointer(SimTypeFunction([SimTypePointer(SimStruct({"Size": SimTypeInt(signed=False, label="UInt32"), "Flags": SimTypeInt(signed=False, label="PRJ_CALLBACK_DATA_FLAGS"), "NamespaceVirtualizationContext": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "CommandId": SimTypeInt(signed=True, label="Int32"), "FileId": SimTypeBottom(label="Guid"), "DataStreamId": SimTypeBottom(label="Guid"), "FilePathName": SimTypePointer(SimTypeChar(label="Char"), offset=0), "VersionInfo": SimTypePointer(SimStruct({"ProviderID": SimTypeFixedSizeArray(SimTypeChar(label="Byte"), 128), "ContentID": SimTypeFixedSizeArray(SimTypeChar(label="Byte"), 128)}, name="PRJ_PLACEHOLDER_VERSION_INFO", pack=False, align=None), offset=0), "TriggeringProcessId": SimTypeInt(signed=False, label="UInt32"), "TriggeringProcessImageFileName": SimTypePointer(SimTypeChar(label="Char"), offset=0), "InstanceContext": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="PRJ_CALLBACK_DATA", pack=False, align=None), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["callbackData", "enumerationId"]), offset=0), "GetDirectoryEnumerationCallback": SimTypePointer(SimTypeFunction([SimTypePointer(SimStruct({"Size": SimTypeInt(signed=False, label="UInt32"), "Flags": SimTypeInt(signed=False, label="PRJ_CALLBACK_DATA_FLAGS"), "NamespaceVirtualizationContext": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "CommandId": SimTypeInt(signed=True, label="Int32"), "FileId": SimTypeBottom(label="Guid"), "DataStreamId": SimTypeBottom(label="Guid"), "FilePathName": SimTypePointer(SimTypeChar(label="Char"), offset=0), "VersionInfo": SimTypePointer(SimStruct({"ProviderID": SimTypeFixedSizeArray(SimTypeChar(label="Byte"), 128), "ContentID": SimTypeFixedSizeArray(SimTypeChar(label="Byte"), 128)}, name="PRJ_PLACEHOLDER_VERSION_INFO", pack=False, align=None), offset=0), "TriggeringProcessId": SimTypeInt(signed=False, label="UInt32"), "TriggeringProcessImageFileName": SimTypePointer(SimTypeChar(label="Char"), offset=0), "InstanceContext": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="PRJ_CALLBACK_DATA", pack=False, align=None), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["callbackData", "enumerationId", "searchExpression", "dirEntryBufferHandle"]), offset=0), "GetPlaceholderInfoCallback": SimTypePointer(SimTypeFunction([SimTypePointer(SimStruct({"Size": SimTypeInt(signed=False, label="UInt32"), "Flags": SimTypeInt(signed=False, label="PRJ_CALLBACK_DATA_FLAGS"), "NamespaceVirtualizationContext": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "CommandId": SimTypeInt(signed=True, label="Int32"), "FileId": SimTypeBottom(label="Guid"), "DataStreamId": SimTypeBottom(label="Guid"), "FilePathName": SimTypePointer(SimTypeChar(label="Char"), offset=0), "VersionInfo": SimTypePointer(SimStruct({"ProviderID": SimTypeFixedSizeArray(SimTypeChar(label="Byte"), 128), "ContentID": SimTypeFixedSizeArray(SimTypeChar(label="Byte"), 128)}, name="PRJ_PLACEHOLDER_VERSION_INFO", pack=False, align=None), offset=0), "TriggeringProcessId": SimTypeInt(signed=False, label="UInt32"), "TriggeringProcessImageFileName": SimTypePointer(SimTypeChar(label="Char"), offset=0), "InstanceContext": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="PRJ_CALLBACK_DATA", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["callbackData"]), offset=0), "GetFileDataCallback": SimTypePointer(SimTypeFunction([SimTypePointer(SimStruct({"Size": SimTypeInt(signed=False, label="UInt32"), "Flags": SimTypeInt(signed=False, label="PRJ_CALLBACK_DATA_FLAGS"), "NamespaceVirtualizationContext": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "CommandId": SimTypeInt(signed=True, label="Int32"), "FileId": SimTypeBottom(label="Guid"), "DataStreamId": SimTypeBottom(label="Guid"), "FilePathName": SimTypePointer(SimTypeChar(label="Char"), offset=0), "VersionInfo": SimTypePointer(SimStruct({"ProviderID": SimTypeFixedSizeArray(SimTypeChar(label="Byte"), 128), "ContentID": SimTypeFixedSizeArray(SimTypeChar(label="Byte"), 128)}, name="PRJ_PLACEHOLDER_VERSION_INFO", pack=False, align=None), offset=0), "TriggeringProcessId": SimTypeInt(signed=False, label="UInt32"), "TriggeringProcessImageFileName": SimTypePointer(SimTypeChar(label="Char"), offset=0), "InstanceContext": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="PRJ_CALLBACK_DATA", pack=False, align=None), offset=0), SimTypeLongLong(signed=False, label="UInt64"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["callbackData", "byteOffset", "length"]), offset=0), "QueryFileNameCallback": SimTypePointer(SimTypeFunction([SimTypePointer(SimStruct({"Size": SimTypeInt(signed=False, label="UInt32"), "Flags": SimTypeInt(signed=False, label="PRJ_CALLBACK_DATA_FLAGS"), "NamespaceVirtualizationContext": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "CommandId": SimTypeInt(signed=True, label="Int32"), "FileId": SimTypeBottom(label="Guid"), "DataStreamId": SimTypeBottom(label="Guid"), "FilePathName": SimTypePointer(SimTypeChar(label="Char"), offset=0), "VersionInfo": SimTypePointer(SimStruct({"ProviderID": SimTypeFixedSizeArray(SimTypeChar(label="Byte"), 128), "ContentID": SimTypeFixedSizeArray(SimTypeChar(label="Byte"), 128)}, name="PRJ_PLACEHOLDER_VERSION_INFO", pack=False, align=None), offset=0), "TriggeringProcessId": SimTypeInt(signed=False, label="UInt32"), "TriggeringProcessImageFileName": SimTypePointer(SimTypeChar(label="Char"), offset=0), "InstanceContext": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="PRJ_CALLBACK_DATA", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["callbackData"]), offset=0), "NotificationCallback": SimTypePointer(SimTypeFunction([SimTypePointer(SimStruct({"Size": SimTypeInt(signed=False, label="UInt32"), "Flags": SimTypeInt(signed=False, label="PRJ_CALLBACK_DATA_FLAGS"), "NamespaceVirtualizationContext": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "CommandId": SimTypeInt(signed=True, label="Int32"), "FileId": SimTypeBottom(label="Guid"), "DataStreamId": SimTypeBottom(label="Guid"), "FilePathName": SimTypePointer(SimTypeChar(label="Char"), offset=0), "VersionInfo": SimTypePointer(SimStruct({"ProviderID": SimTypeFixedSizeArray(SimTypeChar(label="Byte"), 128), "ContentID": SimTypeFixedSizeArray(SimTypeChar(label="Byte"), 128)}, name="PRJ_PLACEHOLDER_VERSION_INFO", pack=False, align=None), offset=0), "TriggeringProcessId": SimTypeInt(signed=False, label="UInt32"), "TriggeringProcessImageFileName": SimTypePointer(SimTypeChar(label="Char"), offset=0), "InstanceContext": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="PRJ_CALLBACK_DATA", pack=False, align=None), offset=0), SimTypeChar(label="Byte"), SimTypeInt(signed=False, label="PRJ_NOTIFICATION"), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimUnion({"PostCreate": SimStruct({"NotificationMask": SimTypeInt(signed=False, label="PRJ_NOTIFY_TYPES")}, name="_PostCreate_e__Struct", pack=False, align=None), "FileRenamed": SimStruct({"NotificationMask": SimTypeInt(signed=False, label="PRJ_NOTIFY_TYPES")}, name="_FileRenamed_e__Struct", pack=False, align=None), "FileDeletedOnHandleClose": SimStruct({"IsFileModified": SimTypeChar(label="Byte")}, name="_FileDeletedOnHandleClose_e__Struct", pack=False, align=None)}, name="<anon>", label="None"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["callbackData", "isDirectory", "notification", "destinationFileName", "operationParameters"]), offset=0), "CancelCommandCallback": SimTypePointer(SimTypeFunction([SimTypePointer(SimStruct({"Size": SimTypeInt(signed=False, label="UInt32"), "Flags": SimTypeInt(signed=False, label="PRJ_CALLBACK_DATA_FLAGS"), "NamespaceVirtualizationContext": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), "CommandId": SimTypeInt(signed=True, label="Int32"), "FileId": SimTypeBottom(label="Guid"), "DataStreamId": SimTypeBottom(label="Guid"), "FilePathName": SimTypePointer(SimTypeChar(label="Char"), offset=0), "VersionInfo": SimTypePointer(SimStruct({"ProviderID": SimTypeFixedSizeArray(SimTypeChar(label="Byte"), 128), "ContentID": SimTypeFixedSizeArray(SimTypeChar(label="Byte"), 128)}, name="PRJ_PLACEHOLDER_VERSION_INFO", pack=False, align=None), offset=0), "TriggeringProcessId": SimTypeInt(signed=False, label="UInt32"), "TriggeringProcessImageFileName": SimTypePointer(SimTypeChar(label="Char"), offset=0), "InstanceContext": SimTypePointer(SimTypeBottom(label="Void"), offset=0)}, name="PRJ_CALLBACK_DATA", pack=False, align=None), offset=0)], SimTypeBottom(label="Void"), arg_names=["callbackData"]), offset=0)}, name="PRJ_CALLBACKS", pack=False, align=None), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypePointer(SimStruct({"Flags": SimTypeInt(signed=False, label="PRJ_STARTVIRTUALIZING_FLAGS"), "PoolThreadCount": SimTypeInt(signed=False, label="UInt32"), "ConcurrentThreadCount": SimTypeInt(signed=False, label="UInt32"), "NotificationMappings": SimTypePointer(SimStruct({"NotificationBitMask": SimTypeInt(signed=False, label="PRJ_NOTIFY_TYPES"), "NotificationRoot": SimTypePointer(SimTypeChar(label="Char"), offset=0)}, name="PRJ_NOTIFICATION_MAPPING", pack=False, align=None), offset=0), "NotificationMappingsCount": SimTypeInt(signed=False, label="UInt32")}, name="PRJ_STARTVIRTUALIZING_OPTIONS", pack=False, align=None), offset=0), SimTypePointer(SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["virtualizationRootPath", "callbacks", "instanceContext", "options", "namespaceVirtualizationContext"]),
        # 
        'PrjStopVirtualizing': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeBottom(label="Void"), arg_names=["namespaceVirtualizationContext"]),
        # 
        'PrjClearNegativePathCache': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt32"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["namespaceVirtualizationContext", "totalEntryNumber"]),
        # 
        'PrjGetVirtualizationInstanceInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimStruct({"InstanceID": SimTypeBottom(label="Guid"), "WriteAlignment": SimTypeInt(signed=False, label="UInt32")}, name="PRJ_VIRTUALIZATION_INSTANCE_INFO", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["namespaceVirtualizationContext", "virtualizationInstanceInfo"]),
        # 
        'PrjMarkDirectoryAsPlaceholder': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimStruct({"ProviderID": SimTypeFixedSizeArray(SimTypeChar(label="Byte"), 128), "ContentID": SimTypeFixedSizeArray(SimTypeChar(label="Byte"), 128)}, name="PRJ_PLACEHOLDER_VERSION_INFO", pack=False, align=None), offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["rootPathName", "targetPathName", "versionInfo", "virtualizationInstanceID"]),
        # 
        'PrjWritePlaceholderInfo': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimStruct({"FileBasicInfo": SimStruct({"IsDirectory": SimTypeChar(label="Byte"), "FileSize": SimTypeLongLong(signed=True, label="Int64"), "CreationTime": SimTypeBottom(label="LARGE_INTEGER"), "LastAccessTime": SimTypeBottom(label="LARGE_INTEGER"), "LastWriteTime": SimTypeBottom(label="LARGE_INTEGER"), "ChangeTime": SimTypeBottom(label="LARGE_INTEGER"), "FileAttributes": SimTypeInt(signed=False, label="UInt32")}, name="PRJ_FILE_BASIC_INFO", pack=False, align=None), "EaInformation": SimStruct({"EaBufferSize": SimTypeInt(signed=False, label="UInt32"), "OffsetToFirstEa": SimTypeInt(signed=False, label="UInt32")}, name="_EaInformation_e__Struct", pack=False, align=None), "SecurityInformation": SimStruct({"SecurityBufferSize": SimTypeInt(signed=False, label="UInt32"), "OffsetToSecurityDescriptor": SimTypeInt(signed=False, label="UInt32")}, name="_SecurityInformation_e__Struct", pack=False, align=None), "StreamsInformation": SimStruct({"StreamsInfoBufferSize": SimTypeInt(signed=False, label="UInt32"), "OffsetToFirstStreamInfo": SimTypeInt(signed=False, label="UInt32")}, name="_StreamsInformation_e__Struct", pack=False, align=None), "VersionInfo": SimStruct({"ProviderID": SimTypeFixedSizeArray(SimTypeChar(label="Byte"), 128), "ContentID": SimTypeFixedSizeArray(SimTypeChar(label="Byte"), 128)}, name="PRJ_PLACEHOLDER_VERSION_INFO", pack=False, align=None), "VariableData": SimTypePointer(SimTypeChar(label="Byte"), offset=0)}, name="PRJ_PLACEHOLDER_INFO", pack=False, align=None), offset=0), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["namespaceVirtualizationContext", "destinationFileName", "placeholderInfo", "placeholderInfoSize"]),
        # 
        'PrjWritePlaceholderInfo2': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimStruct({"FileBasicInfo": SimStruct({"IsDirectory": SimTypeChar(label="Byte"), "FileSize": SimTypeLongLong(signed=True, label="Int64"), "CreationTime": SimTypeBottom(label="LARGE_INTEGER"), "LastAccessTime": SimTypeBottom(label="LARGE_INTEGER"), "LastWriteTime": SimTypeBottom(label="LARGE_INTEGER"), "ChangeTime": SimTypeBottom(label="LARGE_INTEGER"), "FileAttributes": SimTypeInt(signed=False, label="UInt32")}, name="PRJ_FILE_BASIC_INFO", pack=False, align=None), "EaInformation": SimStruct({"EaBufferSize": SimTypeInt(signed=False, label="UInt32"), "OffsetToFirstEa": SimTypeInt(signed=False, label="UInt32")}, name="_EaInformation_e__Struct", pack=False, align=None), "SecurityInformation": SimStruct({"SecurityBufferSize": SimTypeInt(signed=False, label="UInt32"), "OffsetToSecurityDescriptor": SimTypeInt(signed=False, label="UInt32")}, name="_SecurityInformation_e__Struct", pack=False, align=None), "StreamsInformation": SimStruct({"StreamsInfoBufferSize": SimTypeInt(signed=False, label="UInt32"), "OffsetToFirstStreamInfo": SimTypeInt(signed=False, label="UInt32")}, name="_StreamsInformation_e__Struct", pack=False, align=None), "VersionInfo": SimStruct({"ProviderID": SimTypeFixedSizeArray(SimTypeChar(label="Byte"), 128), "ContentID": SimTypeFixedSizeArray(SimTypeChar(label="Byte"), 128)}, name="PRJ_PLACEHOLDER_VERSION_INFO", pack=False, align=None), "VariableData": SimTypePointer(SimTypeChar(label="Byte"), offset=0)}, name="PRJ_PLACEHOLDER_INFO", pack=False, align=None), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypePointer(SimStruct({"InfoType": SimTypeInt(signed=False, label="PRJ_EXT_INFO_TYPE"), "NextInfoOffset": SimTypeInt(signed=False, label="UInt32"), "Anonymous": SimUnion({"Symlink": SimStruct({"TargetName": SimTypePointer(SimTypeChar(label="Char"), offset=0)}, name="_Symlink_e__Struct", pack=False, align=None)}, name="<anon>", label="None")}, name="PRJ_EXTENDED_INFO", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["namespaceVirtualizationContext", "destinationFileName", "placeholderInfo", "placeholderInfoSize", "ExtendedInfo"]),
        # 
        'PrjUpdateFileIfNeeded': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimStruct({"FileBasicInfo": SimStruct({"IsDirectory": SimTypeChar(label="Byte"), "FileSize": SimTypeLongLong(signed=True, label="Int64"), "CreationTime": SimTypeBottom(label="LARGE_INTEGER"), "LastAccessTime": SimTypeBottom(label="LARGE_INTEGER"), "LastWriteTime": SimTypeBottom(label="LARGE_INTEGER"), "ChangeTime": SimTypeBottom(label="LARGE_INTEGER"), "FileAttributes": SimTypeInt(signed=False, label="UInt32")}, name="PRJ_FILE_BASIC_INFO", pack=False, align=None), "EaInformation": SimStruct({"EaBufferSize": SimTypeInt(signed=False, label="UInt32"), "OffsetToFirstEa": SimTypeInt(signed=False, label="UInt32")}, name="_EaInformation_e__Struct", pack=False, align=None), "SecurityInformation": SimStruct({"SecurityBufferSize": SimTypeInt(signed=False, label="UInt32"), "OffsetToSecurityDescriptor": SimTypeInt(signed=False, label="UInt32")}, name="_SecurityInformation_e__Struct", pack=False, align=None), "StreamsInformation": SimStruct({"StreamsInfoBufferSize": SimTypeInt(signed=False, label="UInt32"), "OffsetToFirstStreamInfo": SimTypeInt(signed=False, label="UInt32")}, name="_StreamsInformation_e__Struct", pack=False, align=None), "VersionInfo": SimStruct({"ProviderID": SimTypeFixedSizeArray(SimTypeChar(label="Byte"), 128), "ContentID": SimTypeFixedSizeArray(SimTypeChar(label="Byte"), 128)}, name="PRJ_PLACEHOLDER_VERSION_INFO", pack=False, align=None), "VariableData": SimTypePointer(SimTypeChar(label="Byte"), offset=0)}, name="PRJ_PLACEHOLDER_INFO", pack=False, align=None), offset=0), SimTypeInt(signed=False, label="UInt32"), SimTypeInt(signed=False, label="PRJ_UPDATE_TYPES"), SimTypePointer(SimTypeInt(signed=False, label="PRJ_UPDATE_FAILURE_CAUSES"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["namespaceVirtualizationContext", "destinationFileName", "placeholderInfo", "placeholderInfoSize", "updateFlags", "failureReason"]),
        # 
        'PrjDeleteFile': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypeInt(signed=False, label="PRJ_UPDATE_TYPES"), SimTypePointer(SimTypeInt(signed=False, label="PRJ_UPDATE_FAILURE_CAUSES"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["namespaceVirtualizationContext", "destinationFileName", "updateFlags", "failureReason"]),
        # 
        'PrjWriteFileData': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeBottom(label="Guid"), offset=0), SimTypePointer(SimTypeBottom(label="Void"), offset=0), SimTypeLongLong(signed=False, label="UInt64"), SimTypeInt(signed=False, label="UInt32")], SimTypeInt(signed=True, label="Int32"), arg_names=["namespaceVirtualizationContext", "dataStreamId", "buffer", "byteOffset", "length"]),
        # 
        'PrjGetOnDiskFileState': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeInt(signed=False, label="PRJ_FILE_STATE"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["destinationFileName", "fileState"]),
        # 
        'PrjAllocateAlignedBuffer': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeInt(signed=False, label="UInt"), label="UIntPtr", offset=0)], SimTypePointer(SimTypeBottom(label="Void"), offset=0), arg_names=["namespaceVirtualizationContext", "size"]),
        # 
        'PrjFreeAlignedBuffer': SimTypeFunction([SimTypePointer(SimTypeBottom(label="Void"), offset=0)], SimTypeBottom(label="Void"), arg_names=["buffer"]),
        # 
        'PrjCompleteCommand': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypeInt(signed=True, label="Int32"), SimTypeInt(signed=True, label="Int32"), SimTypePointer(SimStruct({"CommandType": SimTypeInt(signed=False, label="PRJ_COMPLETE_COMMAND_TYPE"), "Anonymous": SimUnion({"Notification": SimStruct({"NotificationMask": SimTypeInt(signed=False, label="PRJ_NOTIFY_TYPES")}, name="_Notification_e__Struct", pack=False, align=None), "Enumeration": SimStruct({"DirEntryBufferHandle": SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)}, name="_Enumeration_e__Struct", pack=False, align=None)}, name="<anon>", label="None")}, name="PRJ_COMPLETE_COMMAND_EXTENDED_PARAMETERS", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["namespaceVirtualizationContext", "commandId", "completionResult", "extendedParameters"]),
        # 
        'PrjFillDirEntryBuffer': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimStruct({"IsDirectory": SimTypeChar(label="Byte"), "FileSize": SimTypeLongLong(signed=True, label="Int64"), "CreationTime": SimTypeBottom(label="LARGE_INTEGER"), "LastAccessTime": SimTypeBottom(label="LARGE_INTEGER"), "LastWriteTime": SimTypeBottom(label="LARGE_INTEGER"), "ChangeTime": SimTypeBottom(label="LARGE_INTEGER"), "FileAttributes": SimTypeInt(signed=False, label="UInt32")}, name="PRJ_FILE_BASIC_INFO", pack=False, align=None), offset=0), SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["fileName", "fileBasicInfo", "dirEntryBufferHandle"]),
        # 
        'PrjFillDirEntryBuffer2': SimTypeFunction([SimTypePointer(SimTypeInt(signed=True, label="Int"), label="IntPtr", offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimStruct({"IsDirectory": SimTypeChar(label="Byte"), "FileSize": SimTypeLongLong(signed=True, label="Int64"), "CreationTime": SimTypeBottom(label="LARGE_INTEGER"), "LastAccessTime": SimTypeBottom(label="LARGE_INTEGER"), "LastWriteTime": SimTypeBottom(label="LARGE_INTEGER"), "ChangeTime": SimTypeBottom(label="LARGE_INTEGER"), "FileAttributes": SimTypeInt(signed=False, label="UInt32")}, name="PRJ_FILE_BASIC_INFO", pack=False, align=None), offset=0), SimTypePointer(SimStruct({"InfoType": SimTypeInt(signed=False, label="PRJ_EXT_INFO_TYPE"), "NextInfoOffset": SimTypeInt(signed=False, label="UInt32"), "Anonymous": SimUnion({"Symlink": SimStruct({"TargetName": SimTypePointer(SimTypeChar(label="Char"), offset=0)}, name="_Symlink_e__Struct", pack=False, align=None)}, name="<anon>", label="None")}, name="PRJ_EXTENDED_INFO", pack=False, align=None), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["dirEntryBufferHandle", "fileName", "fileBasicInfo", "extendedInfo"]),
        # 
        'PrjFileNameMatch': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeChar(label="Byte"), arg_names=["fileNameToCheck", "pattern"]),
        # 
        'PrjFileNameCompare': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0), SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeInt(signed=True, label="Int32"), arg_names=["fileName1", "fileName2"]),
        # 
        'PrjDoesNameContainWildCards': SimTypeFunction([SimTypePointer(SimTypeChar(label="Char"), offset=0)], SimTypeChar(label="Byte"), arg_names=["fileName"]),
    }

lib.set_prototypes(prototypes)