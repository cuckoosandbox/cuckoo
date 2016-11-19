PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE machines (
	id INTEGER NOT NULL,
	name VARCHAR(255) NOT NULL,
	label VARCHAR(255) NOT NULL,
	ip VARCHAR(255) NOT NULL,
	platform VARCHAR(255) NOT NULL,
	locked BOOLEAN NOT NULL,
	locked_changed_on DATETIME,
	status VARCHAR(255),
	status_changed_on DATETIME,
	PRIMARY KEY (id),
	CHECK (locked IN (0, 1))
);
INSERT INTO "machines" VALUES(1,'cuckoo1','cuckoo7','192.168.56.101','windows',1,'2016-11-17 01:42:30.645297','poweroff','2016-11-17 01:42:48.149600');
INSERT INTO "machines" VALUES(2,'cuckoo2','cuckoo8','192.168.56.102','windows',1,null,'poweroff',null);
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
	added_on DATETIME NOT NULL,
	started_on DATETIME,
	completed_on DATETIME,
	status VARCHAR(10) DEFAULT 'pending' NOT NULL,
	sample_id INTEGER,
	PRIMARY KEY (id),
	CHECK (memory IN (0, 1)),
	CHECK (enforce_timeout IN (0, 1)),
	CONSTRAINT status_type CHECK (status IN ('pending', 'processing', 'failure', 'success')),
	FOREIGN KEY(sample_id) REFERENCES samples (id)
);
INSERT INTO "tasks" VALUES(1,'/tmp/msgbox.exe','file',0,1,'','','','','',0,0,'2016-11-17 01:39:45.310733','2016-11-17 01:39:47.861604','2016-11-17 01:39:47.895796','failure',1);
INSERT INTO "tasks" VALUES(2,'/tmp/msgbox.exe','file',0,1,'','','','','',0,0,'2016-11-17 01:39:59.994320','2016-11-17 01:40:04.562919',NULL,'processing',1);
INSERT INTO "tasks" VALUES(3,'/tmp/msgbox.exe','file',0,1,'','','','','',0,0,'2016-11-17 01:40:01.146321','2016-11-17 01:40:16.524363','2016-11-17 01:42:30.154462','success',1);
INSERT INTO "tasks" VALUES(4,'/tmp/msgbox.exe','file',0,1,'','','','','',0,0,'2016-11-17 01:42:51.866503',NULL,NULL,'pending',1);
CREATE TABLE errors (
	id INTEGER NOT NULL,
	message VARCHAR(255) NOT NULL,
	task_id INTEGER NOT NULL,
	PRIMARY KEY (id),
	UNIQUE (task_id),
	FOREIGN KEY(task_id) REFERENCES tasks (id)
);
INSERT INTO "errors" VALUES(1,'hello world',1);
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
INSERT INTO "guests" VALUES(1,'cuckoo1','cuckoo7','VirtualBox','2016-11-17 01:40:04.633518',NULL,2);
INSERT INTO "guests" VALUES(2,'cuckoo1','cuckoo7','VirtualBox','2016-11-17 01:40:16.593367','2016-11-17 01:42:29.781678',3);
INSERT INTO "guests" VALUES(3,'cuckoo1','cuckoo7','VirtualBox','2016-11-17 01:42:30.671561',NULL,4);
COMMIT;
