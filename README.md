# Return-Oriented Programming (ROP) Explanation

@boodamdang

___

### Tại sao có kỹ thuật tấn công ROP?

Sự xuất hiện của các cơ chế bảo vệ như Non-executable (NX) hay Data Execution Prevention (DEP) giúp chống thực thi code ở vùng nhớ không cho phép. Có nghĩa là khi chúng ta khai thác lỗ hổng Buffer Overflow (BOF) của một chương trình, nếu chương trình này có cơ chế bảo vệ NX hay DEP thì shellcode chúng ta chèn vào xem như vô dụng - bởi vì vùng nhớ lưu shellcode đã bị đánh dấu là không được thực thi.

ROP là một kỹ thuật tấn công tận dụng các đoạn code có sẵn của chương trình (đương nhiên là code của chương trình nằm trong vùng nhớ được phép thực thi) để thực thi những lệnh tương đương với việc thực thi shellcode.

### Để hiểu được ROP là như thế nào, trước tiên chúng ta cần hiểu một số cơ chế quan trọng sau:

#### Cấu trúc của stack trong kiến trúc Intel x86 (xần xem kỹ hình bên dưới để biết stack là như thế nào):

![](./pic1.png)

#### Instruction Pointer (IP):  Trỏ tới lệnh đang thực thi trên stack.

#### Stack Pointer (SP): Trỏ tới đỉnh stack.

#### push \<value\>: giảm SP và đẩy \<value\> vào vị trí SP trỏ tới.
  
#### pop \<register\>: lấy giá trị mà SP trỏ tới gán vào \<register\> và tăng SP.

#### call \<function\>:

* push \<return address\> (address của lệnh ngay sau lệnh call \<function\>, tức là lệnh sẽ được thực thi sau khi kết thúc \<function\>) vào stack.

* Gán IP bằng địa chỉ của \<function\>.

#### ret (lệnh ret là mấu chốt của ROP, cần hiểu cơ chế của lệnh pop đã nói ở trên để hiểu rõ lệnh ret):

* pop \<register\>.

* Gán IP bằng giá trị \<register\>.

### Sau khi đã thấm nhuần những tư tưởng bên trên, ta đi vào tìm hiểu ROP là như thế nào:

#### Gadget: Chuỗi các lệnh của chương trình kết thúc bằng lệnh ret. Ví dụ như:

* xor eax, eax ; ret

* inc eax ; ret

* pop eax ; pop edx ; pop ebx ; ret

* mov dword ptr [edx], eax ; ret

* …

#### Ý tưởng của ROP là thực thi liên tiếp chuỗi các gadget (mỗi gadget là chuỗi các lệnh assembly) thay vì thực thi shellcode – bởi vì bản chất shellcode cũng chỉ là chuỗi các lệnh assembly.

