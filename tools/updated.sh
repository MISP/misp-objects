python3 adoc_objects.py >a.txt
mv a.txt objects.txt
asciidoctor-pdf  -a allow-uri-read  objects.txt 
asciidoctor  -a allow-uri-read  objects.txt
cp objects.html ../../misp-website/static
cp objects.pdf ../../misp-website/static
