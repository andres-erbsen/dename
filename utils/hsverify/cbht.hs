import Prelude ((+),(-),(==),(/=),(*),($),(.),(++),(&&),(||),(!!),div,mod,map,take,splitAt,replicate,length,fromIntegral,drop,head,Eq,Show)
import Data.ByteString (ByteString(..),append,cons,pack)
import Data.Word (Word8(..))
import Crypto.Hash.SHA256
type Bool = Word8
data Node = Terminal {h::ByteString, s::[Bool], v::ByteString}
          | Branch   {h::ByteString, s::[Bool], l::Node, r::Node} deriving (Eq,Show)
byte [a,b,c,d, e,f,g,h] = 0x80*a + 0x40*b + 0x20*c + 0x10*d + 8*e + 4*f + 2*g + h
packBits bs = if bs == [] then pack [] else (byte l) `cons` (packBits rr)
  where (l, rr) = splitAt 8 $ bs ++ replicate (7 - (length bs - 1) `mod` 8) 0
bitArr bs = ((l+7)`div`8) `cons` (l`mod`8) `cons` (packBits bs) where l = fromIntegral (length bs)
terminal bs v = Terminal (hash $ bitArr bs `append` (pack $ replicate 64 0) `append` v) bs v
branch bs l r = Branch (hash $ bitArr bs `append` (h l) `append` (h r)) bs l r
withS s (Terminal _ _ v) = terminal s v; withS s (Branch _ _ l r) = branch s l r
commonPrefix (x:xs) (y:ys) = if x == y then x : commonPrefix xs ys else []; commonPrefix _ _ = []
empty = Terminal (pack $ replicate 32 0) [] (pack [])
set k v n = if s n == k || n == empty then terminal k v else
  if s n == common then case k!!(length common) of -- a child of n will take (k,v), now n
    {0 -> branch common (set new v (l n)) (r n); 1 -> branch common (l n) (set new v (r n))}
  else case k!!(length common) of -- k branches of somewhere along (s n)
    {0 -> branch common (terminal new v) (withS old n); 1 -> branch common (withS old n) (terminal new v)}
  where new = drop (length common+1) k; old = drop (length common+1) (s n); common = commonPrefix k (s n)
