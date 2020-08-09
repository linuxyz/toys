#!/bin/sh

IMGS=$(curl -v 'http://www.bing.com/HPImageArchive.aspx?format=xml&idx=0&n=7&mkt=en-US' | sed -e 's/<url>/\n/g' | sed -e 's#</url>#\n#g' | grep '^/th?id=')

# remove all jpeg in current folder
rm -f *.jpg

# Download last 7 days
for url in $IMGS; do
    file=$(echo $url | sed -e 's/.*?id=//' | sed -e 's/&.*//')
    [[ -f "$file" ]] && continue
    curl -v "http://www.bing.com/$url" -o $file
done
