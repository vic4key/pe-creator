#include <cstring>
#include <CatEngine.h>

/* MinGW build EXE with static library
G++ pegen.cpp -lCatEngine -lws2_32 -o pegen.exe && pegen.exe
*/

using namespace ce;

const TCHAR* PE_FILENAME = "pe.exe";
const int	 PE_FILEIZE  = 2048;

int main(int, const char*[])
{
	CcatFile pefile;
	CcatFileMapping fm;
	static void * cBuffer = malloc(PE_FILEIZE);
	memset((void*)cBuffer, 0, PE_FILEIZE);

	pefile.catInit(PE_FILENAME, fgReadWrite, fmCreateAlway, fsReadWrite, faNorm);
	pefile.catWrite(cBuffer, PE_FILEIZE);
	pefile.catClose();

	free(cBuffer);

	/* ... */

	fm.catInit(PE_FILENAME);

	printf("CE -> PE File -> Initialized!\n");

	fm.catCreate(NULL);

	printf("CE -> PE File -> Mapped!\n");

	void * p = fm.catView();

	printf("CE -> PE File -> Loaded!\n");

	if (!p) return 1;

	// Fill file content to zero
	memset(p, 0, fm.catGetFileSize());

	// Dos Header
	TDosHeader * mz = (PDosHeader)p;
	if (!mz) return 1;

	// Dos Header
	mz->e_magic = 0x5A4D;			// 'MZ'
	mz->e_lfanew = 0x40;			// PE Header offset

	printf("CE -> DOS Header -> Created!\n");

	// PE Header
	TPeHeader * pe = (PPeHeader)((unsigned long)p + mz->e_lfanew);
	if (!pe) return 1;

	// File Header
	pe->Signature = 0x00004550;		// 'PE'
	pe->Machine = 0x014C;			// Intel 386
	pe->NumberOfSections = 2;
	pe->SizeOfOptionalHeader = 0x00E0;
	pe->Characteristics = 0x0102;	// File is executable && 32-bit word machine

	// Optional Header
	pe->Magic = 0x010B;				// PE32
	pe->ImageBase = 0x00400000;
	pe->SectionAlignment = 0x1000;
	pe->FileAlignment = 0x200;
	pe->MajorSubsystemVersion = 4;	// The minimum subsystem version required to run the executable
	pe->MinorSubsystemVersion = 0;	// is Windows NT 4.0
	pe->SizeOfHeaders = 0x200;		// Note
	pe->Subsystem = 2;				// Windows GUI
	pe->NumberOfRvaAndSizes = 0x10;

	printf("CE -> PE Header -> Created!\n");

	// Pointer to Section Header
	TSecHeader * sec = (PSecHeader)((unsigned long)pe + sizeof(TNtHeader));

	unsigned long PeData = 0x200;

	// .CODE section
	strncpy((char*)sec->Name, ".CODE", 8);
	sec->PointerToRawData = PeData;
	sec->SizeOfRawData = pe->FileAlignment;
	sec->VirtualAddress = pe->SectionAlignment;
	sec->Misc.VirtualSize = pe->SectionAlignment;
	sec->Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
	// Pointer to .CODE section
	TSecHeader * csec = sec;

	printf("CE -> .CODE Section -> Created!\n");

	// next section
	sec++;

	// .DATA section
	strncpy((char*)sec->Name, ".DATA", 8);
	sec->PointerToRawData = csec->PointerToRawData + csec->SizeOfRawData;
	sec->SizeOfRawData = pe->FileAlignment;
	sec->VirtualAddress = csec->VirtualAddress + csec->Misc.VirtualSize;
	sec->Misc.VirtualSize = pe->SectionAlignment;
	sec->Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
	// Pointer to .DATA section
	TSecHeader * dsec = sec;

	printf("CE -> .DATA Section -> Created!\n");

	// Valid
	pe->AddressOfEntryPoint = csec->VirtualAddress;
	pe->SizeOfImage = dsec->VirtualAddress + dsec->Misc.VirtualSize;
	pe->BaseOfCode = csec->VirtualAddress;
	pe->SizeOfCode = csec->Misc.VirtualSize;
	pe->BaseOfData = dsec->VirtualAddress;

	printf("CE -> PE Header -> Fixed!\n");

	// Import Directory
	pe->Import.VirtualAddress = dsec->VirtualAddress;
	pe->Import.Size = sizeof(TImportDesc);

	printf("CE -> Import Directory -> Created!\n");

	 // Pointer to Import Data, (malloc with 4 empty-block)
	char * idp = (char*)p + dsec->PointerToRawData + 4*sizeof(TImportDesc);
	strcpy((char*)idp, "user32.dll");

	// Pointer to Import Description
	TImportDesc * iid = (PImportDesc)((unsigned long)p + dsec->PointerToRawData);
	char * moduleTable = (char*)iid + 4*sizeof(TImportDesc); // Pointer to Name
	char * thunkTable = (char*)iid + 8*sizeof(TImportDesc);  // Pointer to FirstThunk
	char * thunkData = (char*)iid + 12*sizeof(TImportDesc);  // Pointer to ThunkData

	// Use one IID user32.dll
	strcpy((char*)moduleTable, "user32.dll");
	iid->Name = (unsigned long)(moduleTable - (char*)iid) + dsec->VirtualAddress;
	iid->FirstThunk = (thunkTable - (char*)iid) + dsec->VirtualAddress; // Pointer to IAT

	// APIs gonna import
	const struct {
		const unsigned short Hint;
		const char * Name;
	} apis[] = {
		{0, "MessageBoxA"},
		{1, "MessageBoxW"},
		{2, "MessageBeep"}
	};

	// Generate Import Address Table
	size_t size = 0, napi = sizeof(apis)/sizeof(apis[0]);
	for (int i = 0; i < napi; i++) {
		size = 2 + strlen(apis[i].Name);
		// Save to Thunk Data
		*(unsigned short*)thunkData = apis[i].Hint;
		strcpy(thunkData + 2, apis[i].Name);
		// Save to Thunk Table
		*(unsigned long*)(thunkTable + 4*i) = thunkData - (char*)iid + dsec->VirtualAddress;
		thunkData += (size + 1); // 1-byte for padding
	}

	printf("CE -> IAT -> Created!\n");

	// Program code for testing.
	unsigned char code[] = {
		0x6A, 0x00,							// push	0	MB_OK
		0x68, 0x00, 0x00, 0x00, 0x00,		// push	?	Text (3)
		0x68, 0x00, 0x00, 0x00, 0x00,		// push	?	Caption (8)
		0x6A, 0x00,							// push 0	NULL
		0xFF, 0x15, 0x00, 0x00, 0x00, 0x00, // call MessageBoxA (16)
		0xC3,								// ret
		0x00,
		0x49,0x20,0x61,0x6d,0x20,0x43,		// 'I am CatEngine' string for text message
		0x61,0x74,0x45,0x6e,0x67,0x69,
		0x6e,0x65,0x21,
		0x00,
		0x43,0x61,0x74,0x45,0x6e,0x67,		// 'CatEngine' string for caption message
		0x69,0x6e,0x65,0x00
	};

	unsigned long osOEP = (unsigned long)p + csec->PointerToRawData;
	unsigned long vaOEP = pe->AddressOfEntryPoint + pe->ImageBase;
	unsigned long vaIAT = (unsigned long)thunkTable - (unsigned long)p - dsec->PointerToRawData + dsec->VirtualAddress + pe->ImageBase;

	*(unsigned long*)(&code[8])	 = 0x16 + vaOEP; // Message Caption's VA
	*(unsigned long*)(&code[3])	 = 0x26 + vaOEP; // Message Text's VA
	*(unsigned long*)(&code[16]) = vaIAT + 0;	 // MessageBoxA's VA

	memcpy((void*)osOEP, &code, sizeof(code));

	printf("CE -> Sample Code -> Created!\n");

	fm.catClose();

	printf("CE -> PE File -> Done!\n");

	return 0;
}