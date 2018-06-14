-module(uri_path).

%% API
-export([
  compile_opts/0,
  compile_opts/1,
  compile_empty/0,
  compile_adds/3,
  compile_add/6,
  compile_add_parsed/6,
  compiled2list/1,
  
  decode_no_qs_opts/0,
  decode_no_qs/2,
  
  run_method/3,
  run/3,
  run_element/3,
  
  extra_data2paths_id/2,
  
  
  compile_methods_parse/2,
  compile_path_parse/2,
  paths2paths_id/2
]).


-define(IF(Condition, Then, Else), (case (Condition) of true -> (Then); false -> (Else) end)).

-define(URI_SEPARATOR_BYTE, $/).
-define(URI_SPACE_ALT_BYTE, $+).
-define(URI_ENCODE_HEX_BYTE, $%).
-define(URI_VARIABLE_PREFIX_BYTE, $:).
-define(PATH_ELEMENT_DECODE_PATTERN, binary:compile_pattern([<<?URI_ENCODE_HEX_BYTE>>, <<?URI_SPACE_ALT_BYTE>>])).


-record(compile_opts, {
  path_separator_byte = ?URI_SEPARATOR_BYTE,
  path_variable_prefix_byte = ?URI_VARIABLE_PREFIX_BYTE,
  path_pattern,
  
  methods_separators = [<<" ">>, <<",">>],
  methods_separators_pattern,
  
  methods_allow = #{
    <<"GET">> => <<"GET">>,
    
    <<"POST">> => <<"POST">>,
    
    <<"PUT">> => <<"PUT">>,
    
    <<"DEL">> => <<"DELETE">>,
    <<"DELETE">> => <<"DELETE">>
  },
  
  path_element_decode_pattern, % chars - "+" for space, "%" for hex encode
  
  
  is_allow_path_duplicate = false :: boolean(),
  
  %res - for
  error = null :: null | {binary(), binary(), any()}
}).

-record(decode_opts, {
  decode_pattern
}).


%% compile_opts %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

compile_opts() ->
  {ok, compile_opts__init_(#compile_opts{})}.

compile_opts__init_(#compile_opts{
  path_separator_byte = PS,
  path_variable_prefix_byte = PV,
  methods_separators = MS
} = CompileOpts) ->
  CompileOpts#compile_opts{
    path_pattern = binary:compile_pattern([<<PS>>, <<PV>>]),
    methods_separators_pattern = binary:compile_pattern(MS),
    
    path_element_decode_pattern = ?PATH_ELEMENT_DECODE_PATTERN
  }.

-record(compile_opts_param, {
  type,
  pos
}).

compile_opts(Map)
  when is_map(Map) ->
  PS = #compile_opts_param{type = byte, pos = #compile_opts.path_separator_byte},
  PV = #compile_opts_param{type = byte, pos = #compile_opts.path_variable_prefix_byte},
  MS = #compile_opts_param{type = list_bin, pos = #compile_opts.methods_separators},
  MA = #compile_opts_param{type = map_methods, pos = #compile_opts.methods_allow},
  MapK = #{
    path_separator => PS,
    path_variable_prefix => PV,
    methods_separators => MS,
    methods_allow => MA
  },
  
  case compile_opts__list_(maps:to_list(Map), #compile_opts{}, MapK) of
    {ok, R} ->
      compile_opts__init_(R);
    {error, _} = Err ->
      Err
  end.


compile_opts__list_([{K, V} | Tail], Acc, MapK) ->
  case maps:find(K, MapK) of
    {ok, #compile_opts_param{type = _Type, pos = Pos}} ->
      %todo type
      Acc2 = setelement(Pos, Acc, V),
      compile_opts__list_(Tail, Acc2, MapK);
    error ->
      compile_opts__list_(Tail, Acc, MapK)
  end;
compile_opts__list_([], Acc, _MapK) ->
  {ok, Acc}.


%% compile_adds %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%


-record(compile_path_var, {
  name
}).

-record(path_element, {
  res = null :: any(),
  res_var_names_rev = null :: null | [binary()],
  
  str_map = null :: null | #{},
  var_element = null :: null | #path_element{}
}).

compile_empty() ->
  #{}.

compile_adds(Rows, CompileOpts, AccMap) ->
  compile_adds(Rows, CompileOpts, AccMap, 1, []).

compile_adds([{Path, Methods, ResType, ResData} = Row | Tail], CompileOpts, AccMap, AccIndex, AccErrors) ->
  case compile_add(Path, Methods, ResType, ResData, CompileOpts, AccMap) of
    {ok, AccMap2} ->
      compile_adds(Tail, CompileOpts, AccMap2, AccIndex + 1, AccErrors);
    {error, Err, ErrInfo} ->
      ErrRow = {
        <<"compile_", Err/binary>>,
        AccIndex,
        Row,
        ErrInfo
      },
      compile_adds(Tail, CompileOpts, AccMap, AccIndex + 1, [ErrRow | AccErrors])
  end;
compile_adds([], _CompileOpts, AccMap, _AccIndex, AccErrors) ->
  case AccErrors of
    [] ->
      {ok, AccMap};
    _ ->
      {errors, lists:reverse(AccErrors)}
  end;
compile_adds([RowWrong | Tail], CompileOpts, AccMap, AccIndex, AccErrors) ->
  ErrRow = {
    <<"element">>,
    AccIndex,
    RowWrong,
    null
  },
  compile_adds(Tail, CompileOpts, AccMap, AccIndex + 1, [ErrRow | AccErrors]);
compile_adds(RowsWrong, CompileOpts, AccMap, AccIndex, AccErrors) ->
  ErrRow = {
    <<"list">>,
    AccIndex,
    RowsWrong,
    null
  },
  compile_adds([], CompileOpts, AccMap, AccIndex + 1, [ErrRow | AccErrors]).


compile_add(Path0, Methods0, ResType, ResData, CompileOpts, AccMap) ->
  case compile_methods_parse(Methods0, CompileOpts) of
    {ok, Methods} ->
      case compile_path_parse(Path0, CompileOpts) of
        {ok, Paths} ->
          compile_add_parsed(Paths, Methods, ResType, ResData, CompileOpts, AccMap);
        {error, ErrP, ErrPInfo} ->
          {error, <<"path_", ErrP/binary>>, ErrPInfo}
      end;
    {error, ErrM, ErrMInfo} ->
      {error, <<"methods_", ErrM/binary>>, ErrMInfo}
  end.

compile_add_parsed(Paths, Methods, ResType, ResData, CompileOpts, AccMap) ->
  ExtraData = #{
    inner_paths => Paths
  },
  compile_add__methods_(Methods, Paths, ResType, ResData, CompileOpts, AccMap, [], ExtraData).

compiled2list(Map) when is_map(Map) ->
  maps:to_list(Map).


-define(COMPILE_PARSE_PATH__STRING, 1).
-define(COMPILE_PARSE_PATH__VARIABLE, 2).

compile_path_parse(X, CompileOpts) ->
  Bin = parse_bin(X),
  if
    is_binary(Bin) ->
      Parts = binary:matches(Bin, CompileOpts#compile_opts.path_pattern),
      case compile_parse_parse_parts_(Bin, 0, Parts, ?COMPILE_PARSE_PATH__STRING, [], CompileOpts) of
        {ok, _} = OkRes ->
          OkRes;
        {error, Err, ErrPos} ->
          {error, Err, bin_pos_show(Bin, ErrPos)}
      end;
    true ->
      {error, <<"format">>, X}
  end.

compile_parse_parse_parts_(Bin, Offset, [{Pos, _Len1} | Tail], Parser, Acc, #compile_opts{path_separator_byte = ByteP, path_variable_prefix_byte = ByteV} = CompileOpts) ->
  PosOffset = Pos - Offset,
  <<BinOffset:PosOffset/binary, Byte, BinTail/binary>> = Bin,
  case Parser of
    ?COMPILE_PARSE_PATH__STRING ->
      case Byte of
        ByteP ->
          if
            PosOffset =:= 0 ->
              case Acc of
                [] ->
                  % original Bin start with path separator - allow
                  compile_parse_parse_parts_(BinTail, Offset + 1, Tail, Parser, Acc, CompileOpts);
                _ ->
                  {error, <<"string_empty">>, Pos}
              end;
            true ->
              % acc string
              case path_element_decode(BinOffset, CompileOpts#compile_opts.path_element_decode_pattern) of
                {ok, BinDecode} ->
                  compile_parse_parse_parts_(BinTail, Pos + 1, Tail, Parser, [BinDecode | Acc], CompileOpts);
                {error, ErrDecode, ErrDecodePos} ->
                  {error, <<"decode_", ErrDecode/binary>>, Offset + ErrDecodePos}
              end
          end;
        
        ByteV ->
          if
            PosOffset =:= 0 ->
              compile_parse_parse_parts_(BinTail, Pos + 1, Tail, ?COMPILE_PARSE_PATH__VARIABLE, Acc, CompileOpts); % st variable
            true ->
              {error, <<"variable_start_in_middle">>, Pos}
          end
      end;
    
    ?COMPILE_PARSE_PATH__VARIABLE ->
      case Byte of
        ByteP ->
          if
            PosOffset =:= 0 ->
              {error, <<"variable_empty">>, Pos};
            true ->
              % acc variable
              case path_element_decode(BinOffset, CompileOpts#compile_opts.path_element_decode_pattern) of
                {ok, BinDecode} ->
                  compile_parse_parse_parts_(BinTail, Pos + 1, Tail, ?COMPILE_PARSE_PATH__STRING, [#compile_path_var{name = BinDecode} | Acc], CompileOpts);
                {error, ErrDecode, ErrDecodePos} ->
                  {error, <<"decode_", ErrDecode/binary>>, Offset + ErrDecodePos}
              end
          end;
        
        ByteV ->
          {error, <<"variable_start2">>, Pos}
      end
  end;
compile_parse_parse_parts_(Bin, Offset, [], Parser, Acc, CompileOpts) ->
  case Parser of
    ?COMPILE_PARSE_PATH__STRING ->
      case Bin of
        % original Bin finish with path separator
        <<>> ->
          {ok, lists:reverse(Acc)};
        _ ->
          case path_element_decode(Bin, CompileOpts#compile_opts.path_element_decode_pattern) of
            {ok, BinDecode} ->
              {ok, lists:reverse([BinDecode | Acc])};
            {error, ErrDecode, ErrDecodePos} ->
              {error, <<"decode_", ErrDecode/binary>>, Offset + ErrDecodePos}
          end
      end;
    
    ?COMPILE_PARSE_PATH__VARIABLE ->
      case Bin of
        <<>> ->
          {error, <<"variable_empty">>, Offset};
        _ ->
          case path_element_decode(Bin, CompileOpts#compile_opts.path_element_decode_pattern) of
            {ok, BinDecode} ->
              {ok, lists:reverse([#compile_path_var{name = BinDecode} | Acc])};
            {error, ErrDecode, ErrDecodePos} ->
              {error, <<"decode_", ErrDecode/binary>>, Offset + ErrDecodePos}
          end
      end
  end.



compile_methods_parse(X, CompileOpts) ->
  X2 = parse_bin(X),
  if
    is_binary(X2) ->
      List = binary:split(X2,
        CompileOpts#compile_opts.methods_separators_pattern,
        [global, trim_all]
      ),
      compile_parse_methods2(List, 1, [], CompileOpts#compile_opts.methods_allow);
    true ->
      {error, <<"format">>, X}
  end.

compile_parse_methods2([Bin | Tail], AccIndex, Acc, Map) ->
  BinUp = list_to_binary(string:to_upper(binary_to_list(Bin))),
  case maps:find(BinUp, Map) of
    {ok, Bin2} ->
      compile_parse_methods2(Tail, AccIndex + 1, [Bin2 | Acc], maps:remove(BinUp, Map));
    error ->
      {error, <<"unknown_or_dup">>, {AccIndex, Bin}}
  end;
compile_parse_methods2([], _AccIndex, Acc, _) ->
  case Acc of
    [] ->
      {error, <<"empty">>, null};
    _ ->
      {ok, lists:reverse(Acc)}
  end.




compile_add__methods_([Method | TMethods], Paths, ResType, ResData, CompileOpts, AccMap, AccErrors, ExtraData) ->
  AccElem = path_element_map_get(Method, AccMap, CompileOpts),
  {AccElem2, CompileOpts2} = compile_add__paths_(Method, Paths, ResType, ResData, CompileOpts, AccElem, [], ExtraData),
  AccErrors2 =
    case CompileOpts2#compile_opts.error of
      null ->
        AccErrors;
      Err ->
        [Err | AccErrors]
    end,
  AccMap2 = maps:put(Method, AccElem2, AccMap),
  compile_add__methods_(TMethods, Paths, ResType, ResData, CompileOpts, AccMap2, AccErrors2, ExtraData);
compile_add__methods_([], _Paths, _Res, _ResData, _CompileOpts, AccMap, AccErrors, _ExtraData) ->
  case AccErrors of
    [] ->
      {ok, AccMap};
    _ ->
      {error, <<"add">>, lists:reverse(AccErrors)}
  end.


compile_add__paths_(Method, [PathKey | TPaths], ResType, ResData, CompileOpts, AccElem, AccVarNamesRev, ExtraData) ->
  case PathKey of
    _ when is_binary(PathKey) ->
      %string
      M = AccElem#path_element.str_map,
      {E2, M2} =
        ?IF(M =:= null,
          {#path_element{}, #{}},
          {path_element_map_get(PathKey, M, CompileOpts), M}
        ),
      {E3, CompileOpts3} = compile_add__paths_(Method, TPaths, ResType, ResData, CompileOpts, E2, AccVarNamesRev, ExtraData),
      {
        AccElem#path_element{str_map = maps:put(PathKey, E3, M2)},
        CompileOpts3
      };
    
    #compile_path_var{name = Name} ->
      %variable
      E = AccElem#path_element.var_element,
      E2 = ?IF(E =:= null, #path_element{}, E),
      {E3, CompileOpts3} = compile_add__paths_(Method, TPaths, ResType, ResData, CompileOpts, E2, [Name | AccVarNamesRev], ExtraData),
      {
        AccElem#path_element{var_element = E3},
        CompileOpts3
      }
  end;
compile_add__paths_(Method, [], ResType, ResData, CompileOpts, #path_element{res_var_names_rev = ResVarNamesRes} = AccElem, AccVarNamesRev, ExtraData) ->
  Res = calc_res(ResType, ResData, ExtraData), %todo try
  if
    ResVarNamesRes =:= null ->
      % res is null
      {
        AccElem#path_element{res = Res, res_var_names_rev = AccVarNamesRev},
        CompileOpts
      };
    (ResVarNamesRes =:= AccVarNamesRev), (Res =:= AccElem#path_element.res) ->
      % path repeat - duplicate
      ?IF(CompileOpts#compile_opts.is_allow_path_duplicate,
        {AccElem, CompileOpts},
        {AccElem, CompileOpts#compile_opts{
          error = {Method, <<"repeat">>, duplicate}
        }}
      );
    true ->
      % path repeat - not duplicate
      {AccElem, CompileOpts#compile_opts{
        error = {Method, <<"repeat">>, {
          lists:reverse(AccVarNamesRev), % show variables in normal order
          lists:reverse(ResVarNamesRes)
        }}
      }}
  end.

calc_res(ResType, ResData, ExtraData) ->
  case ResType of
    data ->
      ResData;
    fun2 ->
      {Fun2, Data1} = ResData,
      Fun2(Data1, ExtraData)
  end.

extra_data2paths_id(_, #{inner_paths := Paths}) ->
  paths2paths_id(Paths, []).

paths2paths_id([PathKey | TPaths], Acc) ->
  Acc2 = ?IF(Acc =:= [], Acc, [?URI_SEPARATOR_BYTE | Acc]),
  Z =
    case PathKey of
      _ when is_binary(PathKey) ->
        %string
        PathKey;
      
      #compile_path_var{} ->
        ?URI_VARIABLE_PREFIX_BYTE
    end,
  paths2paths_id(TPaths, [Z | Acc2]);
paths2paths_id([], Acc) ->
  iolist_to_binary(lists:reverse(Acc)).



path_element_map_get(K, Map, _CompileOpts) ->
  case maps:find(K, Map) of
    {ok, V} ->
      V;
    error ->
      #path_element{}
  end.


path_element_decode(Bin, PathElementDecodePattern) ->
  case binary:matches(Bin, PathElementDecodePattern) of
    [] ->
      {ok, Bin};
    Parts ->
      case path_element_decode(Bin, 0, Parts, []) of
        {ok, IoList} ->
          {ok, iolist_to_binary(IoList)};
        Err ->
          Err
      end
  end.

path_element_decode(Bin, Offset, [{Pos, _Len1} | Tail], Acc) ->
  PosOffset = Pos - Offset,
  <<BinOffset:PosOffset/binary, Byte, BinTail/binary>> = Bin,
  case Byte of
    ?URI_ENCODE_HEX_BYTE ->
      case BinTail of
        <<Hex1, Hex2, BinTail2/binary>> ->
          HexNum1 = hex2num(Hex1),
          HexNum2 = hex2num(Hex2),
          if
            is_integer(HexNum1), is_integer(HexNum2) ->
              HexByte = (HexNum1 bsl 4) bor HexNum2,
              path_element_decode(BinTail2, Pos + 3, Tail, [HexByte, BinOffset | Acc]);
            true ->
              {error, <<"hex_format">>, Pos}
          end;
        _ ->
          {error, <<"hex_part">>, Pos}
      end;
    ?URI_SPACE_ALT_BYTE ->
      path_element_decode(BinTail, Pos + 1, Tail, [$\s, BinOffset | Acc])
  end;
path_element_decode(Bin, _Offset, [], Acc) ->
  {ok, lists:reverse([Bin | Acc])}.


%% path_parse %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

decode_no_qs_opts() ->
  P = binary:compile_pattern([
    <<?URI_SEPARATOR_BYTE>>,
    <<?URI_ENCODE_HEX_BYTE>>,
    <<?URI_SPACE_ALT_BYTE>>
  ]),
  {ok, #decode_opts{
    decode_pattern = P
  }}.

decode_no_qs(<<?URI_SEPARATOR_BYTE, Bin/binary>>, #decode_opts{decode_pattern = Pattern}) ->
  case binary:matches(Bin, Pattern) of
    [] ->
      case Bin of
        <<>> ->
          {ok, []};
        _ ->
          {ok, [Bin]}
      end;
    Parts ->
      case path_decode_no_qs__parts_(Bin, 0, Parts, [], []) of
        {ok, _} = ResOk ->
          ResOk;
        {error, Err, ErrPos} ->
          {error, Err, bin_pos_show(Bin, ErrPos)}
      end
  end;
decode_no_qs(Other, _Pattern) ->
  {error, <<"format">>, Other}.


path_decode_no_qs__parts_(Bin, Offset, [{Pos, _Len1} | Tail], AccStr, Acc) ->
  PosOffset = Pos - Offset,
  <<BinOffset:PosOffset/binary, Byte, BinTail/binary>> = Bin,
  case Byte of
    ?URI_SEPARATOR_BYTE ->
      if
        PosOffset > 0 ->
          Str = ?IF(AccStr =:= [],
            BinOffset,
            iolist_to_binary(lists:reverse([BinOffset | AccStr]))
          ),
          path_decode_no_qs__parts_(BinTail, Pos + 1, Tail, [], [Str | Acc]);
        true ->
          % PosOffset =:= 0
          Str = ?IF(AccStr =:= [],
            <<>>, % no trim right (and center)
            iolist_to_binary(lists:reverse(AccStr))
          ),
          path_decode_no_qs__parts_(BinTail, Pos + 1, Tail, [], [Str | Acc])
      end;
    
    ?URI_ENCODE_HEX_BYTE ->
      case BinTail of
        <<Hex1, Hex2, BinTail2/binary>> ->
          HexNum1 = hex2num(Hex1),
          HexNum2 = hex2num(Hex2),
          if
            is_integer(HexNum1), is_integer(HexNum2) ->
              HexByte = (HexNum1 bsl 4) bor HexNum2,
              ?IF(PosOffset > 0,
                path_decode_no_qs__parts_(BinTail2, Pos + 3, Tail, [HexByte, BinOffset | AccStr], Acc),
                path_decode_no_qs__parts_(BinTail2, Pos + 3, Tail, [HexByte | AccStr], Acc)
              );
            true ->
              {error, <<"hex_format">>, Pos}
          end;
        _ ->
          {error, <<"hex_part">>, Pos}
      end;
    
    ?URI_SPACE_ALT_BYTE ->
      ?IF(PosOffset > 0,
        path_decode_no_qs__parts_(BinTail, Pos + 1, Tail, [$\s, BinOffset | AccStr], Acc),
        path_decode_no_qs__parts_(BinTail, Pos + 1, Tail, [$\s | AccStr], Acc)
      )
  end;
path_decode_no_qs__parts_(Bin, _Offset, [], AccStr, Acc) ->
  case AccStr of
    [] ->
      Acc2 =
        case Bin of
          <<>> ->
            Acc; % trim right
          _ ->
            [Bin | Acc]
        end,
      {ok, lists:reverse(Acc2)};
    _ ->
      Str = iolist_to_binary(
        case Bin of
          <<>> ->
            AccStr;
          _ ->
            [Bin | AccStr]
        end),
      {ok, lists:reverse([Str | Acc])}
  end.


%% paths %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

run_method(Method, Paths, MapMethods) ->
  case maps:find(Method, MapMethods) of
    {ok, E} ->
      run(Paths, E, []);
    error ->
      {error, 404, <<"not_found_method">>}
  end.

run([PathKey | TPath], #path_element{str_map = S} = E, AccVarValsRev) ->
  if
    S =/= null ->
      case maps:find(PathKey, S) of
        {ok, E2} ->
          run(TPath, E2, AccVarValsRev);
        error ->
          ?IF(E#path_element.var_element =/= null,
            run(TPath, E#path_element.var_element, [PathKey | AccVarValsRev]),
            {error, 404, <<"not_found_path">>}
          )
      end;
    E#path_element.var_element =/= null ->
      run(TPath, E#path_element.var_element, [PathKey | AccVarValsRev]);
    true ->
      {error, 404, <<"not_found_path">>}
  end;
run([], #path_element{res_var_names_rev = ResVarNamesRev} = E, AccVarValsRev) ->
  ?IF(ResVarNamesRev =/= null,
    {ok, E#path_element.res, ResVarNamesRev, AccVarValsRev},
    {error, 404, <<"not_found_res">>}
  ).


run_element([PathKey | TPath], #path_element{str_map = S} = E, AccVarValsRev) ->
  if
    S =/= null ->
      case maps:find(PathKey, S) of
        {ok, E2} ->
          run(TPath, E2, AccVarValsRev);
        error ->
          ?IF(E#path_element.var_element =/= null,
            run(TPath, E#path_element.var_element, [PathKey | AccVarValsRev]),
            {error, 404, <<"not_found_path">>}
          )
      end;
    E#path_element.var_element =/= null ->
      run(TPath, E#path_element.var_element, [PathKey | AccVarValsRev]);
    true ->
      {error, 404, <<"not_found_path">>}
  end;
run_element([], #path_element{} = E, AccVarValsRev) ->
  {ok, E, AccVarValsRev}.


%% utils %%%%%%%%%%%%%5%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%



is_str_bytes([X | Tail]) ->
  if
    is_integer(X), X =< 255, X >= 0 ->
      is_str_bytes(Tail);
    true ->
      false
  end;
is_str_bytes("") ->
  true;
is_str_bytes(_) ->
  false.


parse_bin(X) ->
  case is_list(X) andalso is_str_bytes(X) of
    true ->
      list_to_binary(X);
    false ->
      X
  end.




hex2num(B) ->
  if
    is_integer(B) ->
      case B of
        $0 -> 0;
        $1 -> 1;
        $2 -> 2;
        $3 -> 3;
        $4 -> 4;
        $5 -> 5;
        $6 -> 6;
        $7 -> 7;
        $8 -> 8;
        $9 -> 9;
        $A -> 10;
        $B -> 11;
        $C -> 12;
        $D -> 13;
        $E -> 14;
        $F -> 15;
        $a -> 10;
        $b -> 11;
        $c -> 12;
        $d -> 13;
        $e -> 14;
        $f -> 15;
        _ -> error
      end;
    true ->
      error
  end.

bin_pos_show(Bin, Pos)
  when is_binary(Bin), is_integer(Pos) ->
  case Bin of
    <<BinBefore:Pos/binary, BinAfter/binary>> ->
      {Pos, BinBefore, BinAfter};
    _ ->
      {Pos, Bin, wrong_pos}
  end.


