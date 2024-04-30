CLEANFILES=zig-cache zig-out ./dinky ./dinky.o
PORT=8088

help:
	@echo "Usage: make install - build the dinky executable"
	@echo "       make serve   - start dinky and print the website link"
	@echo "       make list    - prints all make targets"

install:
	@zig build-exe -O ReleaseSmall -fstrip -fomit-frame-pointer dinky.zig -target x86_64-freestanding && strip -R .comment ./dinky

serve:
	@echo "Serving on http://localhost:$(PORT)"
	@./dinky $(PORT) index.html text/html

clean:
	@rm -rf $(CLEANFILES)
	@echo Done removing $(CLEANFILES)

list:
	@grep '^[^#.[:space:]].*:' Makefile | sed 's/://'
