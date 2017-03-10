PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE tags (
	id INTEGER NOT NULL,
	name VARCHAR(255) NOT NULL,
	PRIMARY KEY (id),
	UNIQUE (name)
);
CREATE TABLE alembic_version (
	version_num VARCHAR(32) NOT NULL,
	PRIMARY KEY (version_num)
);
INSERT INTO "alembic_version" VALUES('263a45963c72');
CREATE TABLE samples (
	id INTEGER NOT NULL,
	file_size INTEGER NOT NULL,
	file_type VARCHAR(255) NOT NULL,
	md5 VARCHAR(32) NOT NULL,
	crc32 VARCHAR(8) NOT NULL,
	sha1 VARCHAR(40) NOT NULL,
	sha256 VARCHAR(64) NOT NULL,
	sha512 VARCHAR(128) NOT NULL,
	ssdeep VARCHAR(255),
	PRIMARY KEY (id)
);
INSERT INTO "samples" VALUES(1,2048,'PE32 executable (GUI) Intel 80386 (stripped to external PDB), for MS Windows','e1590ab0ba8fa41b4b8396a7b8370154','C56B25A6','3f3617b860e16f02fc3434c511d37efc3b2db75a','212153e5e27996d1dd7d9e01921781cf6d9426aba552017ec5e30714b61e9981','3ccc2ff27b10a0b6722e98595f47fb41ff1bf5af91ade424834b00e1dae7114de8a314ebdbdc9683a2347949fb1140b8f41382800af205d47e8ce1a7803d971d',NULL);
CREATE TABLE machines (
	id INTEGER NOT NULL,
	name VARCHAR(255) NOT NULL,
	label VARCHAR(255) NOT NULL,
	ip VARCHAR(255) NOT NULL,
	platform VARCHAR(255) NOT NULL,
	interface VARCHAR(255),
	snapshot VARCHAR(255),
	locked BOOLEAN NOT NULL,
	locked_changed_on DATETIME,
	status VARCHAR(255),
	status_changed_on DATETIME,
	resultserver_ip VARCHAR(255) NOT NULL,
	resultserver_port VARCHAR(255) NOT NULL,
	PRIMARY KEY (id),
	CHECK (locked IN (0, 1))
);
INSERT INTO "machines" VALUES(1,'cuckoo1','cuckoo1','192.168.56.101','windows',NULL,NULL,0,'2017-02-07 12:28:56.136458','poweroff','2017-02-07 12:28:55.371252','192.168.56.1','2042');
CREATE TABLE machines_tags (
	machine_id INTEGER,
	tag_id INTEGER,
	FOREIGN KEY(machine_id) REFERENCES machines (id),
	FOREIGN KEY(tag_id) REFERENCES tags (id)
);
CREATE TABLE tasks (
	id INTEGER NOT NULL,
	target TEXT NOT NULL,
	category VARCHAR(255) NOT NULL,
	timeout INTEGER DEFAULT '0' NOT NULL,
	priority INTEGER DEFAULT '1' NOT NULL,
	custom VARCHAR(255),
	machine VARCHAR(255),
	package VARCHAR(255),
	options VARCHAR(255),
	platform VARCHAR(255),
	memory BOOLEAN NOT NULL,
	enforce_timeout BOOLEAN NOT NULL,
	clock DATETIME NOT NULL,
	added_on DATETIME NOT NULL,
	started_on DATETIME,
	completed_on DATETIME,
	status VARCHAR(9) DEFAULT 'pending' NOT NULL,
	sample_id INTEGER,
	PRIMARY KEY (id),
	CHECK (memory IN (0, 1)),
	CHECK (enforce_timeout IN (0, 1)),
	CONSTRAINT status_type CHECK (status IN ('pending', 'running', 'completed', 'reported', 'recovered')),
	FOREIGN KEY(sample_id) REFERENCES samples (id)
);
INSERT INTO "tasks" VALUES(1,'/home/jbr/git/samples/msgbox.exe','file',0,1,'custom1','','','human=1','',0,0,'2017-02-07 12:28:29.693550','2017-02-07 12:28:29.693566','2017-02-07 12:28:34.374064','2017-02-07 12:28:56.186526','reported',1);
INSERT INTO "tasks" VALUES(2,'/home/jbr/git/samples/msgbox.exe','file',0,1,'','','','','',0,0,'2017-02-07 12:30:09.118495','2017-02-07 12:30:09.118507',NULL,NULL,'pending',1);
CREATE TABLE errors (
	id INTEGER NOT NULL,
	message VARCHAR(255) NOT NULL,
	task_id INTEGER NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(task_id) REFERENCES tasks (id)
);
CREATE TABLE tasks_tags (
	task_id INTEGER,
	tag_id INTEGER,
	FOREIGN KEY(task_id) REFERENCES tasks (id),
	FOREIGN KEY(tag_id) REFERENCES tags (id)
);
CREATE TABLE guests (
	id INTEGER NOT NULL,
	name VARCHAR(255) NOT NULL,
	label VARCHAR(255) NOT NULL,
	manager VARCHAR(255) NOT NULL,
	started_on DATETIME NOT NULL,
	shutdown_on DATETIME,
	task_id INTEGER NOT NULL,
	PRIMARY KEY (id),
	UNIQUE (task_id),
	FOREIGN KEY(task_id) REFERENCES tasks (id)
);
INSERT INTO "guests" VALUES(1,'cuckoo1','cuckoo1','VirtualBox','2017-02-07 12:28:34.486156','2017-02-07 12:28:55.448725',1);
CREATE UNIQUE INDEX hash_index ON samples (md5, crc32, sha1, sha256, sha512);
COMMIT;
