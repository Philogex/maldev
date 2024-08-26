; ModuleID = 'win64_llvm.bc'
source_filename = "llvm-link"
target datalayout = "e-m:w-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-w64-windows-gnu"

module asm ".globl _ZSt21ios_base_library_initv"
module asm ".globl _ZSt21ios_base_library_initv"

%"class.std::basic_ostream" = type { ptr, %"class.std::basic_ios" }
%"class.std::basic_ios" = type { %"class.std::ios_base", ptr, i8, i8, ptr, ptr, ptr, ptr }
%"class.std::ios_base" = type { ptr, i64, i64, i32, i32, i32, ptr, %"struct.std::ios_base::_Words", [8 x %"struct.std::ios_base::_Words"], i32, ptr, %"class.std::locale" }
%"struct.std::ios_base::_Words" = type <{ ptr, i32, [4 x i8] }>
%"class.std::locale" = type { ptr }

@.str = private unnamed_addr constant [25 x i8] c"Yippie from Subfunction.\00", align 1
@_ZSt4cout = external global %"class.std::basic_ostream", align 8
@.str.1 = private unnamed_addr constant [14 x i8] c"Hello, World!\00", align 1
@.str.1.2 = private unnamed_addr constant [6 x i8] c"ntdll\00", align 1
@.str.2 = private unnamed_addr constant [19 x i8] c"NtMapViewOfSection\00", align 1

; Function Attrs: mustprogress noinline optnone uwtable
define dso_local void @_Z15exampleFunctionv() #0 {
  %1 = call noundef nonnull align 8 dereferenceable(8) ptr @_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc(ptr noundef nonnull align 8 dereferenceable(8) @_ZSt4cout, ptr noundef @.str)
  %2 = call noundef nonnull align 8 dereferenceable(8) ptr @_ZNSolsEPFRSoS_E(ptr noundef nonnull align 8 dereferenceable(8) %1, ptr noundef @_ZSt4endlIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_)
  ret void
}

declare dso_local noundef nonnull align 8 dereferenceable(8) ptr @_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc(ptr noundef nonnull align 8 dereferenceable(8), ptr noundef) #1

declare dso_local noundef nonnull align 8 dereferenceable(8) ptr @_ZSt4endlIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_(ptr noundef nonnull align 8 dereferenceable(8)) #1

declare dso_local noundef nonnull align 8 dereferenceable(8) ptr @_ZNSolsEPFRSoS_E(ptr noundef nonnull align 8 dereferenceable(8), ptr noundef) #1

; Function Attrs: mustprogress noinline norecurse optnone uwtable
define dso_local noundef i32 @main() #2 {
  %1 = alloca i32, align 4
  %2 = alloca i32, align 4
  %3 = alloca i32, align 4
  %4 = alloca i32, align 4
  %5 = alloca ptr, align 8
  %6 = alloca ptr, align 8
  store i32 0, ptr %1, align 4
  %7 = call noundef nonnull align 8 dereferenceable(8) ptr @_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc(ptr noundef nonnull align 8 dereferenceable(8) @_ZSt4cout, ptr noundef @.str.1)
  %8 = call noundef nonnull align 8 dereferenceable(8) ptr @_ZNSolsEPFRSoS_E(ptr noundef nonnull align 8 dereferenceable(8) %7, ptr noundef @_ZSt4endlIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_)
  store volatile i32 42, ptr %2, align 4
  %9 = load volatile i32, ptr %2, align 4
  %10 = mul nsw i32 %9, 2
  store i32 %10, ptr %3, align 4
  %11 = load i32, ptr %3, align 4
  %12 = mul nsw i32 %11, 69
  store i32 %12, ptr %4, align 4
  call void @_Z15exampleFunctionv()
  %13 = call ptr @LoadLibraryA(ptr noundef @.str.1.2)
  store ptr %13, ptr %6, align 8
  %14 = icmp ne ptr %13, null
  br i1 %14, label %16, label %15

15:                                               ; preds = %0
  store i32 -1, ptr %1, align 4
  br label %21

16:                                               ; preds = %0
  %17 = load ptr, ptr %6, align 8
  %18 = call ptr @GetProcAddress(ptr noundef %17, ptr noundef @.str.2)
  store ptr %18, ptr %5, align 8
  %19 = load ptr, ptr %5, align 8
  %20 = call noundef i32 %19(ptr noundef null, ptr noundef null, ptr noundef null, i32 noundef 0, i32 noundef 0, ptr noundef null, ptr noundef null, i32 noundef 0, i32 noundef 0, i32 noundef 0)
  store i32 0, ptr %1, align 4
  br label %21

21:                                               ; preds = %16, %15
  %22 = load i32, ptr %1, align 4
  ret i32 %22
}

declare dllimport ptr @LoadLibraryA(ptr noundef) #1

declare dllimport ptr @GetProcAddress(ptr noundef, ptr noundef) #1

attributes #0 = { mustprogress noinline optnone uwtable "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #1 = { "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #2 = { mustprogress noinline norecurse optnone uwtable "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }

!llvm.ident = !{!0, !0}
!llvm.module.flags = !{!1, !2, !3}

!0 = !{!"Debian clang version 16.0.6 (27+b1)"}
!1 = !{i32 1, !"wchar_size", i32 2}
!2 = !{i32 8, !"PIC Level", i32 2}
!3 = !{i32 7, !"uwtable", i32 2}
