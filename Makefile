all: MESSENINE.class
	cd src && java MESSENINE

MESSENINE.class:
	cd src && javac MESSENINE.java -encoding utf8
