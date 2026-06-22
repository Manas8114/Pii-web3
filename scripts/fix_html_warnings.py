import re
from pathlib import Path

def fix_html_files(templates_dir, static_css_dir):
    templates_path = Path(templates_dir)
    static_css_path = Path(static_css_dir)
    static_css_path.mkdir(parents=True, exist_ok=True)
    
    extracted_css_path = static_css_path / 'extracted_inline.css'
    
    css_rules = []
    counter = [1]
    
    # regex patterns
    style_pattern = re.compile(r'\bstyle\s*=\s*(["\'])(.*?)\1', re.IGNORECASE)
    empty_link_pattern = re.compile(r'<a\s+([^>]*href\s*=\s*["\'][^"\']*["\'][^>]*)>\s*</a>', re.IGNORECASE)
    
    for html_file in templates_path.glob('*.html'):
        with open(html_file, 'r', encoding='utf-8') as f:
            content = f.read()
            
        modified = False
        
        # 1. Fix backdrop-filter order
        # Ensure -webkit comes before the standard property
        if 'backdrop-filter' in content and '-webkit-backdrop-filter' in content:
            # We'll rely on the CSS extraction to handle this in standard classes, 
            # but if it's in a <style> tag:
            content = re.sub(r'(backdrop-filter:[^;]+;)\s*(-webkit-backdrop-filter:[^;]+;)', r'\2 \1', content)
            modified = True
            
        # 2. Add title to empty links
        def link_repl(match):
            attrs = match.group(1)
            if 'title=' not in attrs.lower():
                return f'<a {attrs} title="link"></a>'
            return match.group(0)
            
        new_content = empty_link_pattern.sub(link_repl, content)
        if new_content != content:
            content = new_content
            modified = True
            
        # 3. Extract inline styles
        def style_repl(match):
            nonlocal modified
            style_content = match.group(2).strip()
            if not style_content:
                return match.group(0)
                
            # fix backdrop filter order inside inline style before extraction
            if 'backdrop-filter' in style_content and '-webkit-backdrop-filter' in style_content:
                style_content = re.sub(r'(backdrop-filter:[^;]+;)\s*(-webkit-backdrop-filter:[^;]+;)', r'\2 \1', style_content)
                
            class_name = f"auto-style-{counter[0]}"
            counter[0] += 1
            
            css_rules.append(f".{class_name} {{\n    {style_content}\n}}")
            
            modified = True
            return f'class="{class_name}"'
            
        # We need to make sure we append to existing class attributes instead of replacing style with class
        # if a class already exists. This is complex for a simple regex, so we'll do a two-pass for safety:
        # First, find style="...", extract it, replace with class="auto-style-X"
        # If the element already had a class, it will result in <div class="..." class="auto-style-X">
        # Browsers handle multiple class attributes poorly, so we should merge them. 
        # For a hackathon fix script, merging class attributes:
        
        # Replace styles
        content_extracted_styles = style_pattern.sub(style_repl, content)
        
        # Merge multiple classes (very basic merge)
        content_merged = re.sub(r'class=(["\'])(.*?)\1\s+class=(["\'])(.*?)\3', r'class="\2 \4"', content_extracted_styles)
        while content_merged != content_extracted_styles:
            content_extracted_styles = content_merged
            content_merged = re.sub(r'class=(["\'])(.*?)\1\s+class=(["\'])(.*?)\3', r'class="\2 \4"', content_extracted_styles)
            
        if content_merged != content:
            content = content_merged
            modified = True
            
        # Make sure the extracted_inline.css is linked in the <head>
        if modified and '<head>' in content and 'extracted_inline.css' not in content:
            content = content.replace('<head>', '<head>\n    <link rel="stylesheet" href="{{ url_for(\'static\', filename=\'css/extracted_inline.css\') }}">')
            
        if modified:
            with open(html_file, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f"Fixed {html_file.name}")
            
    if css_rules:
        existing_css = ""
        if extracted_css_path.exists():
            with open(extracted_css_path, 'r', encoding='utf-8') as f:
                existing_css = f.read() + "\n\n"
                
        with open(extracted_css_path, 'w', encoding='utf-8') as f:
            f.write(existing_css + "\n".join(css_rules))
        print(f"Extracted {len(css_rules)} inline styles to {extracted_css_path}")

if __name__ == "__main__":
    base_dir = Path(__file__).parent.parent
    fix_html_files(base_dir / 'templates', base_dir / 'static' / 'css')
