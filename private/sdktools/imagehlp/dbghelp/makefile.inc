PRE_DEF_DONE=1
$(OBJ_PATH)\$(O)\dbghelp.def:  ..\imagehlp.src
    @$(_TYPE) <<$(ECHO_RSP)
<<$(BUILD_NOKEEP)
    @$(C_PREPROCESSOR_NAME) @<<$(CL_RSP) /Tc"..\imagehlp.src" > $@
$(CPPXX: =
)
-DPRIVATE=
<<$(BUILD_NOKEEP)


$(OBJ_PATH)\$(O)\dbghelp.lib: $(OBJ_PATH)\$(O)\dbghelp.def $(IMPLIB_DEPEND)
    $(LIB_NAME) /out:$(@R).lib @<<$(LIB_RESPONSE_FILE)
$(LIBRARIAN_FLAGS: =
)
-def:$(OBJ_PATH)\$(O)\dbghelp.def
$(LIBRARY_OBJS: =
)
<<$(BUILD_NOKEEP)
