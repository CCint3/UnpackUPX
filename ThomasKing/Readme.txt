IDA dump 内存
static main(void)
{
  auto fp, begin, end, dexbyte;
  fp = fopen("C:\\dump.dex", "wb");
  begin = 0xb3b71000;
  end = begin + 0x8000;
  for ( dexbyte = begin; dexbyte < end; dexbyte ++ )
    fputc(Byte(dexbyte), fp);
}

---------------------------------------------------------

libfoo.so为原始apk中的so文件便于重建后对比，dump.so为从内存中dump出的so。

1. 使用correctDump.bat，完成对dump.so内存对齐的修正。
2. 使用rebuildSection.bat，完成section重建。

PS:
restoreSection.bat用于原so文件有section情况下时使用。
				



				----ThomasKing 2014.09.30
---------------------------------------------------------
更正由于文件操作不当导致restoreSection.bat不修复ELF32_header
0058836C

				----ThomasKing 2014.10.10