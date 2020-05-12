/**
 * This is an example that manually created a PE file format with a minimum required, minimum
 * PE format structure fields have to use and can not be missed of a PE file.
 * This can help you to understand the PE file format, the work-flow for creating a PE file,
 * for manual unpacking, for IAT fixing, etc.
 *
 * References
 * - https://en.wikipedia.org/wiki/Portable_Executable
 * - https://docs.microsoft.com/en-us/windows/win32/debug/pe-format
 * - https://docs.microsoft.com/en-us/archive/msdn-magazine/2002/february/inside-windows-win32-portable-executable-file-format-in-detail
 */

#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <cassert>
#include <vector>
#include <map>

#include <vu> /* https://github.com/vic4key/Vutils */

using namespace vu;

template<typename Ptr>
size_t StrCpyT(Ptr p, const std::string& s)
{
  strncpy(reinterpret_cast<char*>(p), s.c_str(), s.length());
  return s.size();
}

#define ToRVA(pSH, p) (DWORD(p) - DWORD(pBase) - pSH->PointerToRawData + pSH->VirtualAddress)
#define ToVA(pSH, p) (DWORD(p) - DWORD(pBase) - pSH->PointerToRawData + pSH->VirtualAddress + pPE->ImageBase)

int main(int, const char*[])
{
  CBuffer bin(3*KiB);

  const auto pBase = reinterpret_cast<PBYTE>(bin.GetpData());

  // DOS Header

  const auto pDOS = PDOSHeader(pBase);
  pDOS->e_magic = IMAGE_DOS_SIGNATURE; // 'MZ'
  pDOS->e_lfanew = 0x80; // For this example, default PE Header offset

  std::cout << "PE -> DOS Header -> Created" << std::endl;

  // PE Header (NT Header + Data Directory = Signature + File Header + Optional Header + Data Directory)

  const auto pPE = PPEHeader(DWORD(pBase) + pDOS->e_lfanew);

  pPE->Signature = IMAGE_NT_SIGNATURE; // 'PE'

  // File Header

  pPE->Machine = IMAGE_FILE_MACHINE_I386; // Can only be run on machine architecture is Intel 386
  // pPE->NumberOfSections = ?; // TODO: Fixup Later
  pPE->SizeOfOptionalHeader = sizeof(TOptHeader);
  pPE->Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_32BIT_MACHINE; // File is executable on 32-bit machine

  // Optional Header

  pPE->Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC; // PE32
  // pPE->SizeOfCode = ? ; // TODO: Fixup Later
  // pPE->AddressOfEntryPoint = ? ; // TODO: Fixup Later
  // pPE->BaseOfCode = ? ; // TODO: Fixup Later
  // pPE->BaseOfData = ? ; // TODO: Fixup Later
  pPE->ImageBase = 0x00400000; // For this example
  pPE->SectionAlignment = 0x1000; // For this example
  pPE->FileAlignment = 0x200; // For this example
  pPE->MajorSubsystemVersion = 5; // The minimum Subsystem version required to run the executable
  pPE->MinorSubsystemVersion = 2; // Windows NT 5.2
  // pPE->SizeOfImage = ?;   // TODO: Fixup Later
  // pPE->SizeOfHeaders = ?; // TODO: Fixup Later
  pPE->SubSystem = IMAGE_SUBSYSTEM_WINDOWS_GUI; // Windows GUI
  pPE->NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES; // Almost, set to max number of directory entries

  std::cout << "PE -> PE Header -> Created" << std::endl;

  // Section Header(s)

  std::cout << "PE -> Section Headers -> Created" << std::endl;

  auto pSH = PSectionHeader(DWORD(pPE) + sizeof(TNTHeader)); // The Section Header(s) after the NT Header

  // For this example, default offset after the last section header, refer to pPE->SizeOfHeaders
  const DWORD PEBody = 0x200;
  static int  iSH = 0;

  PSectionHeader pSHLast = nullptr;

  // For this example,
  // Default the raw/virtual offset is continuous file offset + raw size of previous section
  // Default the raw/virtual size is equal to OptHeader.FileAlignment/OptHeader.SectionAlignment
  const auto AddSectionHeader = [&](const std::string& name, const DWORD characteristics) -> PSectionHeader
  {
    PSectionHeader result = nullptr;

    static TSectionHeader empty = { 0 };
    ZeroMemory(&empty, sizeof(empty));
    empty.PointerToRawData = PEBody;
    empty.SizeOfRawData = pPE->FileAlignment;
    empty.Misc.VirtualSize = pPE->SectionAlignment;

    const auto pPrevSection = iSH == 0 ? &empty : pSH - 1;
    assert(pPrevSection != nullptr);

    StrCpyT(pSH->Name, name.c_str());
    pSH->PointerToRawData = pPrevSection->PointerToRawData + pPrevSection->SizeOfRawData;
    pSH->SizeOfRawData = pPE->FileAlignment;
    pSH->VirtualAddress = pPrevSection->VirtualAddress + pPrevSection->Misc.VirtualSize;
    pSH->Misc.VirtualSize = pPE->SectionAlignment;
    pSH->Characteristics = characteristics;

    result = pSH;

    std::cout << "PE -> Section Header -> " << name.c_str() << " -> Created" << std::endl;

    iSH++;
    pSH++;

    pSHLast = result;

    return result;
  };

  // Add .code section
  const auto pSHCode = AddSectionHeader(
    ".code", IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE);

  // Add .data section
  const auto pSHData = AddSectionHeader(
    ".data", IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE);

  // Add .idata section
  const auto pSHImport = AddSectionHeader(
    ".idata", IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE);

  // Fixup PE Header

  pPE->NumberOfSections = iSH;
  pPE->AddressOfEntryPoint = pSHCode->VirtualAddress;
  pPE->BaseOfCode = pSHCode->VirtualAddress;
  pPE->SizeOfCode = pSHCode->Misc.VirtualSize;
  pPE->BaseOfData = pSHData->VirtualAddress;
  pPE->SizeOfImage = pSHLast->VirtualAddress + pSHLast->Misc.VirtualSize;
  pPE->SizeOfHeaders = VU_ALIGN_UP(DWORD(PBYTE(pSH) - pBase), pPE->FileAlignment); // The offset after the last section is the end / combined-size of all headers.

  std::cout << "PE -> PE Header -> Fixed" << std::endl;

  // Import Directory

  pPE->Import.VirtualAddress = pSHImport->VirtualAddress;
  pPE->Import.Size = sizeof(TImportDescriptor);

  std::cout << "PE -> Import Directories -> Created" << std::endl;

  typedef std::pair<ushort, std::string> ImportByName;
  std::map<std::string, std::vector<ImportByName>> m;
  std::vector<ImportByName> l;

  l.clear();
  l.push_back(ImportByName(0, "MessageBoxA"));
  m["user32.dll"] = l;

  auto pIDT = PImportDescriptor(pBase + pSHImport->PointerToRawData);

  // Create IDT, IAT, ILT for each DLL
  // - IDT -> Import Directory Table that Array<IID>
  // - IAT -> Import Address Table that Array<Thunk Data>
  // - ILT -> Import Lookup Table that Array<Hint, Function>

  /* Write them all in .idata section
   * Array<IDT> | Array<IAT | DLL | ILT>
   * or
   * |--- Array for <IDT>
   * | IDT / Import Descriptor (s) / 20 bytes for each dll / padding 1 IDT = 20 bytes
   * |--- Array for <IAT, DLL, ILT>
   * |  | IAT / Thunk Table / 4 bytes for each function / padding 1 DWORD = 4 bytes
   * |  |---
   * |  | DLL / DLL Name / depends on dll name / any padding
   * |  |---
   * |  | ILT / Thunk Data / import by name (s) / depends on function hint/name / any padding
   * |  |---
  */

  // Total size of IDTs
  const auto TotalSizeIDTs = (m.size() + 1) * sizeof(TImportDescriptor); // +1 for an empty IDD
  auto pPtr = PBYTE(pIDT) + TotalSizeIDTs;

  for (const auto& e : m)
  {
    auto pIAT = PDWORD(pPtr);
    auto rvaIAT = ToRVA(pSHImport, pIAT);

    const auto EachIATSize = (e.second.size() + 1) * sizeof(DWORD); // +1 DWORD for IAT padding
    pPtr += EachIATSize;

    // Write hint/name of import functions of each DLL

    StrCpyT(pPtr, e.first.c_str());
    auto rvaName = ToRVA(pSHImport, pPtr);

    pPtr += e.first.size() + 1; // +1 for a null-char padding

    for (const auto& ibn : e.second) // image import by name (s)
    {
      *PWORD(pPtr) = ibn.first; // Hint
      StrCpyT(pPtr + sizeof(WORD), ibn.second.c_str()); // Name

      *pIAT++ = ToRVA(pSHImport, pPtr); // Update Thunk Data for each import function in IAT

      pPtr += sizeof(WORD) + ibn.second.size() + 2; // +2 for string terminating null-character & a null-char padding
    }

    // Update IDT for each DLL

    pIDT->Name = rvaName;
    pIDT->FirstThunk = rvaIAT;
    pIDT->OriginalFirstThunk = rvaIAT;

    std::cout << "PE -> Import Directory -> " << e.first << " -> Created" << std::endl;

    pIDT++; // Next IDD
  }

  pIDT++; // Next an empty IDD to mark end of IDT array

  // Executable Codes

  BYTE code[] =
  {
    0x6A, 0x40,                         // push 40 uType = MB_ICONINFORMATION + MB_OK
    0x68, 0x00, 0x00, 0x00, 0x00,       // push ?  lpCaption = ? (offset 3)  // TODO: Fixup Later
    0x68, 0x00, 0x00, 0x00, 0x00,       // push ?  lpText = ?    (offset 8)  // TODO: Fixup Later
    0x6A, 0x00,                         // push 0  hWnd = NULL
    0xFF, 0x15, 0x00, 0x00, 0x00, 0x00, // call MessageBoxA = ? (offset 16) // TODO: Fixup Later
    0xC3,                               // ret
  };

  // Write data such as message, caption, etc to .data section

  auto pData = pBase + pSHData->PointerToRawData;

  auto len = StrCpyT(pData, "Howdy, Vic P.");
  const auto vaCaption = ToVA(pSHData, pData);
  pData += len + 1; // +1 for string terminating null-character

  StrCpyT(pData, "This is an example that manually created a PE file format");
  const auto vaText = ToVA(pSHData, pData);
  pData += len + 1; // +1 for string terminating null-character

  // Correct API callee to imported functions that defined in the IAT

  pIDT = PImportDescriptor(pBase + pSHImport->PointerToRawData);
  auto pIAT = PBYTE(pIDT) + TotalSizeIDTs;
  const auto vaMessageBoxA = ToVA(pSHImport, pIAT); // For this example, IAT contains only one this API, so treat IAT offset as its offset

  std::cout << "PE -> Executable Codes -> Created" << std::endl;

  // Fixup Executable Codes

  *PDWORD(&code[8])  = vaText;
  *PDWORD(&code[3])  = vaCaption;
  *PDWORD(&code[16]) = vaMessageBoxA;

  const auto OEP = pBase + pSHCode->PointerToRawData;
  CopyMemory(OEP, &code, sizeof(code));

  std::cout << "PE -> Executable Codes -> Fixed" << std::endl;

  // Save To File

  bin.SaveAsFile(_T("PE.EXE"));

  std::cout << "PE -> File -> Created" << std::endl;

  return 0;
}
