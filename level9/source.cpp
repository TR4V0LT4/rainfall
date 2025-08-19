Main Function :
  void main(int param_1, int param_2) {
    N *this;
    N *this_00;
    if (param_1 < 2) {
      _exit(1);  // Exit if no argv[1]
    }
    this = (N *)operator_new(0x6c);  // Allocate first N object (108 bytes)
    N::N(this, 5);  // Initialize with value 5
    this_00 = (N *)operator_new(0x6c);  // Allocate second N object
    N::N(this_00, 6);  // Initialize with value 6
    N::setAnnotation(this, *(char **)(param_2 + 4));  // Copy argv[1]
    (*(code *)**(undefined4 **)this_00)(this_00, this);  // Call vtable function
    return;
  }

N Constructor :
  void __thiscall N::N(N *this, int param_1) {
    *(undefined ***)this = &PTR_operator__08048848;  // Set vtable
    *(int *)(this + 0x68) = param_1;  // Set value at offset 0x68
    return;
  }
  
setAnnotation:
  void __thiscall N::setAnnotation(N *this, char *param_1) {
    size_t __n = strlen(param_1);
    memcpy(this + 4, param_1, __n);  // Vulnerable copy
    return;
  }

Vtable Functions:
int __thiscall N::operator+(N *this, N *param_1) {
  return *(int *)(param_1 + 0x68) + *(int *)(this + 0x68);
}
int __thiscall N::operator-(N *this, N *param_1) 