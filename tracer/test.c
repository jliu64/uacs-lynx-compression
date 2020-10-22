
void test2() {
	int x = -1;
}

int test() {
	test2();
	return 1;
}

int main() {
	int x = test();
	return 0;
}
