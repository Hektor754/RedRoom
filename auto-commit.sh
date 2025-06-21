git status --porcelain | awk '{print $2}' | while read file; do
  git add "$file"
  git commit -m "Update $file"
done

git push
