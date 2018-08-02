package io.pnyx.bubu.bubuj;

import com.github.jtendermint.jabci.types.RequestCheckTx;
import com.github.jtendermint.jabci.types.RequestCommit;
import com.google.protobuf.ByteString;
import com.google.protobuf.Descriptors;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.Map;

public class AbciBuilderTest {

    @Test
    public void testBuildCommit() {
        ByteString bs = ByteString.copyFrom("hèllo", StandardCharsets.UTF_8);
        RequestCheckTx rc = RequestCheckTx.newBuilder().setTx(bs).build();

    }
}
