target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

@age = global i32 20
@array = global [17 x i8] zeroinitializer


%struct.T = type { i8, i32 }
define i32 @main(i32 %argc, i8** %argv) {
	%arr_ptr = getelementptr [17 x i8], [17 x i8]* @array, i32 1
	%ele_ptr = getelementptr [17 x i8], [17 x i8]* @array, i32 0, i32 0
	%1 = call i32 @Add(i32 1, i32 2)
	%2 = mul i32 %1, 7
	%3 = icmp eq i32 %2, 42
	%res = zext i1 %3 to i32
	ret i32 %res
}

define i32 @Add(i32 %0, i32 %1) {
	%3 = add i32 %0, %1
	ret i32 %3
}

define {i32, i8} @fun() {
	ret {i32, i8} {i32 8, i8 4}
}

define i32 @factorial(i32 %val) {
	%is_base_case = icmp eq i32 %val, 0
	br i1 %is_base_case, label %base_case, label %recursive_case
base_case:
	ret i32 1
recursive_case:
	%1 = add i32 -1, %val
	%2 = call i32 @factorial(i32 %1)
	%3 = mul i32 %val, %2
	ret i32 %3
}

define i32 @factoriall(i32 %val) {
entry:
	br label %check_for_condition
check_for_condition:
	%i = phi i32 [2, %entry], [%i_plus_one, %for_body]
	%temp = phi i32 [1, %entry], [%new_temp, %for_body]
	%i_leq_val = icmp sle i32 %i, %val
	br i1 %i_leq_val, label %for_body, label %end_loop
for_body:
	%new_temp = mul i32 %temp, %i
	%i_plus_one = add i32 %i, 1
	br label %check_for_condition
end_loop:
	ret i32 %temp
}
 
define i32 @factorialll(i32 %val) {
entry:
	%i.addr = alloca i32
	%temp.addr = alloca i32
	store i32 2, i32* %i.addr
	store i32 1, i32* %temp.addr
	br label %check_for_condition
check_for_condition:
	%i = load i32, i32* %i.addr
	%temp = load i32, i32* %temp.addr
	%i_leq_val = icmp sle i32 %i, %val
	br i1 %i_leq_val, label %for_body, label %end_loop
for_body:
	%new_temp = mul i32 %temp, %i
	%i_plus_one = add i32 %i, 1
	store i32 %i_plus_one, i32* %i.addr
	store i32 %new_temp, i32* %temp.addr
	br label %check_for_condition
end_loop:
	ret i32 %temp
}
 
