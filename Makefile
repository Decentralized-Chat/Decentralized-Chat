all: MESSENINE.class
	cd src && java MESSENINE

MESSENINE.class:
	cd src && javac MESSENINE.java -encoding utf8

clean:
	cd src && del *.class
