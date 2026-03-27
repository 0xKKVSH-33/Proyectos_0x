
echo off
cls
echo bienvenido a mi scrip
echo  Hecho_por_JUAN

echo primer analisis: guardando reporte de comando ipconfig
ipconfig > reporte-ipconfig.txt
echo reporte generado con exito
echo ______________________________________________________________________

echo segundo analisis: guardando reporte de comando ipconfig-/all:
ipconfig /all  > reporte-ipconfig-all.txt
echo reporte generado con exito
echo ______________________________________________________________________

echo Tercer analisis: guardando reporte de comando ping-8.8.8.8
ping 8.8.8.8 > reporte-ping-8.8.8.8.txt
echo reporte generado con exito
echo ______________________________________________________________________

echo Cuarto analisis: guardando reporte de comando netstat -ano
netstat -ano > reporte-netstat-ano.txt
echo reporte generado con exito
echo ______________________________________________________________________

echo Quinto analisis: guardando reporte de comando tracert google.com
tracert google.com > reporte-tracert-google.com.txt
echo reporte generado con exito
echo ______________________________________________________________________


echo todos los comandos han sido generado con exito
echo gracias por utilizar mi scrip
echo on
