import os

def extract_patch(patch_file):
    with open(patch_file, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    current_file = None
    file_content = []

    for line in lines:
        if line.startswith('+++ b/'):
            # Save the previous file if we were parsing one
            if current_file:
                save_file(current_file, file_content)
            current_file = line[6:].strip()
            file_content = []
        elif current_file and line.startswith('+') and not line.startswith('+++'):
            # Append the line, stripping the leading '+' character
            file_content.append(line[1:])
        elif current_file and line.startswith('diff --git'):
            # Reset when hitting the next file block
            if current_file:
                save_file(current_file, file_content)
            current_file = None
            file_content = []

    # Save the final file in the loop
    if current_file:
        save_file(current_file, file_content)

def save_file(filepath, content):
    # Create directories if they do not exist
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, 'w', encoding='utf-8') as f:
        f.writelines(content)
    print(f"Successfully extracted: {filepath}")

if __name__ == '__main__':
    extract_patch('phase5.patch')