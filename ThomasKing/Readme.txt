IDA dump �ڴ�
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

libfoo.soΪԭʼapk�е�so�ļ������ؽ���Աȣ�dump.soΪ���ڴ���dump����so��

1. ʹ��correctDump.bat����ɶ�dump.so�ڴ�����������
2. ʹ��rebuildSection.bat�����section�ؽ���

PS:
restoreSection.bat����ԭso�ļ���section�����ʱʹ�á�
				



				----ThomasKing 2014.09.30
---------------------------------------------------------
���������ļ�������������restoreSection.bat���޸�ELF32_header
0058836C

				----ThomasKing 2014.10.10