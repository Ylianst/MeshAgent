#!/bin/bash
name=meshagent

mkdir $name.iconset
rm -rf $name.iconset/*
#sips -z 16 16     $name.png --out $name.iconset/icon_16x16
#sips -z 32 32     $name.png --out $name.iconset/icon_16x16@2x
#sips -z 32 32     $name.png --out $name.iconset/icon_32x32
#sips -z 64 64     $name.png --out $name.iconset/icon_32x32@2x
#sips -z 128 128   $name.png --out $name.iconset/icon_128x128
#sips -z 256 256   $name.png --out $name.iconset/icon_128x128@2x
#sips -z 256 256   $name.png --out $name.iconset/icon_256x256
#sips -z 512 512   $name.png --out $name.iconset/icon_256x256@2x
sips -z 512 512   $name.png --out $name.iconset/icon_512x512
#cp $name.png $name.iconset/icon_512x512@2x

pngquant --ext .png ./$name.iconset/*
sleep 1
find ./$name.iconset -maxdepth 1 -type f ! -name "*.png" -delete
iconutil -c icns $name.iconset

#iconutil -c icns $largeICON.iconset