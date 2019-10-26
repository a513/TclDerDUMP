tclderdump
------
tclderdump утилита командной строки для просмотра ASN1-структур.
Утилита написана на скриптовом языке tcl (derdump.tcl).
Также представлены утилиты командной строки для платформ Linux, Windows и OS X. 
Они полностью самодостаточны.
Синтаксис утилиты:

$derdump <разбираемый файл> <файл для результата | stdout> <0 | 1> <der | pem| hex> 

Если в качестве второго параметра задано stdout, то результат будет выводиться в стандартный вывод.
Если третий параметр равен 1, то будет выводиться дополнительная информация.
Последний параметр указывает на формат файла. Отметим, что вшестнадцатеричном формате 
могут присутствовать спецсимволя \n, \t, \r, а также символы ":", "." и пробелы.
Например:
$tclderdump__linux64  guc_gost12.pem stdout 1 pem  

Loading file: guc_gost12.pem  

LEN=1304  

30 C-Sequence  82 05 14 (1300)  

   30 C-Sequence  82 04 c1 (1217)  
   
      a0 C-[0]  03 (3)  
      
         02 Integer  01 (1)  
         
            02   
            
      02 Integer  10 (16)  
      
         4e 6d 47 8b 26 f2 7d 65 7f 76 8e 02 5c e3 d3 93  
         
      30 C-Sequence  0a (10)  
      
         06 Object Identifier  08 (8)  
         
            1 2 643 7 1 1 3 2 (GOST R 34.10-2012-256 with GOSTR 34.11-2012-256)  
            
            2a 85 03 07 01 01 03 02   
            
. . .  

   30 C-Sequence  0a (10)  
   
      06 Object Identifier  08 (8)  
      
         1 2 643 7 1 1 3 2 (GOST R 34.10-2012-256 with GOSTR 34.11-2012-256)  
         
         2a 85 03 07 01 01 03 02   
         
   03 Bit String  41 (65)  
   
      00 9a fa fd e2 3b ac 72 fb f8 5b 10 9e 81 f6 8b a0 d5 c6 a6 a5 6c   
      
      8c 4b 2a 3d 39 79 da 59 18 f2 cb 6f a0 76 3d 30 0c c9 ae e9 4a df  
      
      61 6f c4 27 14 00 60 b1 1e 08 13 98 13 e1 55 64 0d 66 d7 fe 7e  
        
        
$  


Просмотр ASN-структуры из файла в шестнадцатеричном формате :
$tclderdump__linux64 hex_from_py.hex  stdout 1 hex

Автор - [Орлов Владимир](http://museum.lissi-crypto.ru/)

Email: vorlov@lissi.ru
Copyright(C) [LISSI-Soft Ltd](http://soft.lissi.ru) 2019-2019
P.S. Имеется также реализация данной [утилиты с графическим интерфейсом](https://habr.com/ru/post/468817/)
