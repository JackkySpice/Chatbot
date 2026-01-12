.class public final Landroidx/appcompat/view/menu/hc0$a;
.super Landroidx/appcompat/view/menu/hc0;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Landroidx/appcompat/view/menu/hc0;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "a"
.end annotation


# instance fields
.field public final b:Landroidx/appcompat/view/menu/gc0;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/gc0;)V
    .locals 1

    const-string v0, "mMeasurementManager"

    invoke-static {p1, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Landroidx/appcompat/view/menu/hc0;-><init>()V

    iput-object p1, p0, Landroidx/appcompat/view/menu/hc0$a;->b:Landroidx/appcompat/view/menu/gc0;

    return-void
.end method

.method public static final synthetic d(Landroidx/appcompat/view/menu/hc0$a;)Landroidx/appcompat/view/menu/gc0;
    .locals 0

    iget-object p0, p0, Landroidx/appcompat/view/menu/hc0$a;->b:Landroidx/appcompat/view/menu/gc0;

    return-object p0
.end method


# virtual methods
.method public b()Landroidx/appcompat/view/menu/g90;
    .locals 7
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Landroidx/appcompat/view/menu/g90;"
        }
    .end annotation

    invoke-static {}, Landroidx/appcompat/view/menu/em;->a()Landroidx/appcompat/view/menu/mh;

    move-result-object v0

    invoke-static {v0}, Landroidx/appcompat/view/menu/th;->a(Landroidx/appcompat/view/menu/jh;)Landroidx/appcompat/view/menu/sh;

    move-result-object v1

    const/4 v2, 0x0

    const/4 v3, 0x0

    new-instance v4, Landroidx/appcompat/view/menu/hc0$a$b;

    const/4 v0, 0x0

    invoke-direct {v4, p0, v0}, Landroidx/appcompat/view/menu/hc0$a$b;-><init>(Landroidx/appcompat/view/menu/hc0$a;Landroidx/appcompat/view/menu/wg;)V

    const/4 v5, 0x3

    const/4 v6, 0x0

    invoke-static/range {v1 .. v6}, Landroidx/appcompat/view/menu/a9;->b(Landroidx/appcompat/view/menu/sh;Landroidx/appcompat/view/menu/jh;Landroidx/appcompat/view/menu/wh;Landroidx/appcompat/view/menu/xw;ILjava/lang/Object;)Landroidx/appcompat/view/menu/nk;

    move-result-object v1

    const/4 v2, 0x1

    invoke-static {v1, v0, v2, v0}, Landroidx/appcompat/view/menu/ih;->c(Landroidx/appcompat/view/menu/nk;Ljava/lang/Object;ILjava/lang/Object;)Landroidx/appcompat/view/menu/g90;

    move-result-object v0

    return-object v0
.end method

.method public c(Landroid/net/Uri;)Landroidx/appcompat/view/menu/g90;
    .locals 7
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Landroid/net/Uri;",
            ")",
            "Landroidx/appcompat/view/menu/g90;"
        }
    .end annotation

    const-string v0, "trigger"

    invoke-static {p1, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {}, Landroidx/appcompat/view/menu/em;->a()Landroidx/appcompat/view/menu/mh;

    move-result-object v0

    invoke-static {v0}, Landroidx/appcompat/view/menu/th;->a(Landroidx/appcompat/view/menu/jh;)Landroidx/appcompat/view/menu/sh;

    move-result-object v1

    const/4 v2, 0x0

    const/4 v3, 0x0

    new-instance v4, Landroidx/appcompat/view/menu/hc0$a$d;

    const/4 v0, 0x0

    invoke-direct {v4, p0, p1, v0}, Landroidx/appcompat/view/menu/hc0$a$d;-><init>(Landroidx/appcompat/view/menu/hc0$a;Landroid/net/Uri;Landroidx/appcompat/view/menu/wg;)V

    const/4 v5, 0x3

    const/4 v6, 0x0

    invoke-static/range {v1 .. v6}, Landroidx/appcompat/view/menu/a9;->b(Landroidx/appcompat/view/menu/sh;Landroidx/appcompat/view/menu/jh;Landroidx/appcompat/view/menu/wh;Landroidx/appcompat/view/menu/xw;ILjava/lang/Object;)Landroidx/appcompat/view/menu/nk;

    move-result-object p1

    const/4 v1, 0x1

    invoke-static {p1, v0, v1, v0}, Landroidx/appcompat/view/menu/ih;->c(Landroidx/appcompat/view/menu/nk;Ljava/lang/Object;ILjava/lang/Object;)Landroidx/appcompat/view/menu/g90;

    move-result-object p1

    return-object p1
.end method

.method public e(Landroidx/appcompat/view/menu/gl;)Landroidx/appcompat/view/menu/g90;
    .locals 7
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Landroidx/appcompat/view/menu/gl;",
            ")",
            "Landroidx/appcompat/view/menu/g90;"
        }
    .end annotation

    const-string v0, "deletionRequest"

    invoke-static {p1, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {}, Landroidx/appcompat/view/menu/em;->a()Landroidx/appcompat/view/menu/mh;

    move-result-object v0

    invoke-static {v0}, Landroidx/appcompat/view/menu/th;->a(Landroidx/appcompat/view/menu/jh;)Landroidx/appcompat/view/menu/sh;

    move-result-object v1

    const/4 v2, 0x0

    const/4 v3, 0x0

    new-instance v4, Landroidx/appcompat/view/menu/hc0$a$a;

    const/4 v0, 0x0

    invoke-direct {v4, p0, p1, v0}, Landroidx/appcompat/view/menu/hc0$a$a;-><init>(Landroidx/appcompat/view/menu/hc0$a;Landroidx/appcompat/view/menu/gl;Landroidx/appcompat/view/menu/wg;)V

    const/4 v5, 0x3

    const/4 v6, 0x0

    invoke-static/range {v1 .. v6}, Landroidx/appcompat/view/menu/a9;->b(Landroidx/appcompat/view/menu/sh;Landroidx/appcompat/view/menu/jh;Landroidx/appcompat/view/menu/wh;Landroidx/appcompat/view/menu/xw;ILjava/lang/Object;)Landroidx/appcompat/view/menu/nk;

    move-result-object p1

    const/4 v1, 0x1

    invoke-static {p1, v0, v1, v0}, Landroidx/appcompat/view/menu/ih;->c(Landroidx/appcompat/view/menu/nk;Ljava/lang/Object;ILjava/lang/Object;)Landroidx/appcompat/view/menu/g90;

    move-result-object p1

    return-object p1
.end method

.method public f(Landroid/net/Uri;Landroid/view/InputEvent;)Landroidx/appcompat/view/menu/g90;
    .locals 7
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Landroid/net/Uri;",
            "Landroid/view/InputEvent;",
            ")",
            "Landroidx/appcompat/view/menu/g90;"
        }
    .end annotation

    const-string v0, "attributionSource"

    invoke-static {p1, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {}, Landroidx/appcompat/view/menu/em;->a()Landroidx/appcompat/view/menu/mh;

    move-result-object v0

    invoke-static {v0}, Landroidx/appcompat/view/menu/th;->a(Landroidx/appcompat/view/menu/jh;)Landroidx/appcompat/view/menu/sh;

    move-result-object v1

    const/4 v2, 0x0

    const/4 v3, 0x0

    new-instance v4, Landroidx/appcompat/view/menu/hc0$a$c;

    const/4 v0, 0x0

    invoke-direct {v4, p0, p1, p2, v0}, Landroidx/appcompat/view/menu/hc0$a$c;-><init>(Landroidx/appcompat/view/menu/hc0$a;Landroid/net/Uri;Landroid/view/InputEvent;Landroidx/appcompat/view/menu/wg;)V

    const/4 v5, 0x3

    const/4 v6, 0x0

    invoke-static/range {v1 .. v6}, Landroidx/appcompat/view/menu/a9;->b(Landroidx/appcompat/view/menu/sh;Landroidx/appcompat/view/menu/jh;Landroidx/appcompat/view/menu/wh;Landroidx/appcompat/view/menu/xw;ILjava/lang/Object;)Landroidx/appcompat/view/menu/nk;

    move-result-object p1

    const/4 p2, 0x1

    invoke-static {p1, v0, p2, v0}, Landroidx/appcompat/view/menu/ih;->c(Landroidx/appcompat/view/menu/nk;Ljava/lang/Object;ILjava/lang/Object;)Landroidx/appcompat/view/menu/g90;

    move-result-object p1

    return-object p1
.end method

.method public g(Landroidx/appcompat/view/menu/p71;)Landroidx/appcompat/view/menu/g90;
    .locals 7
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Landroidx/appcompat/view/menu/p71;",
            ")",
            "Landroidx/appcompat/view/menu/g90;"
        }
    .end annotation

    const-string v0, "request"

    invoke-static {p1, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {}, Landroidx/appcompat/view/menu/em;->a()Landroidx/appcompat/view/menu/mh;

    move-result-object v0

    invoke-static {v0}, Landroidx/appcompat/view/menu/th;->a(Landroidx/appcompat/view/menu/jh;)Landroidx/appcompat/view/menu/sh;

    move-result-object v1

    const/4 v2, 0x0

    const/4 v3, 0x0

    new-instance v4, Landroidx/appcompat/view/menu/hc0$a$e;

    const/4 v0, 0x0

    invoke-direct {v4, p0, p1, v0}, Landroidx/appcompat/view/menu/hc0$a$e;-><init>(Landroidx/appcompat/view/menu/hc0$a;Landroidx/appcompat/view/menu/p71;Landroidx/appcompat/view/menu/wg;)V

    const/4 v5, 0x3

    const/4 v6, 0x0

    invoke-static/range {v1 .. v6}, Landroidx/appcompat/view/menu/a9;->b(Landroidx/appcompat/view/menu/sh;Landroidx/appcompat/view/menu/jh;Landroidx/appcompat/view/menu/wh;Landroidx/appcompat/view/menu/xw;ILjava/lang/Object;)Landroidx/appcompat/view/menu/nk;

    move-result-object p1

    const/4 v1, 0x1

    invoke-static {p1, v0, v1, v0}, Landroidx/appcompat/view/menu/ih;->c(Landroidx/appcompat/view/menu/nk;Ljava/lang/Object;ILjava/lang/Object;)Landroidx/appcompat/view/menu/g90;

    move-result-object p1

    return-object p1
.end method

.method public h(Landroidx/appcompat/view/menu/q71;)Landroidx/appcompat/view/menu/g90;
    .locals 7
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Landroidx/appcompat/view/menu/q71;",
            ")",
            "Landroidx/appcompat/view/menu/g90;"
        }
    .end annotation

    const-string v0, "request"

    invoke-static {p1, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {}, Landroidx/appcompat/view/menu/em;->a()Landroidx/appcompat/view/menu/mh;

    move-result-object v0

    invoke-static {v0}, Landroidx/appcompat/view/menu/th;->a(Landroidx/appcompat/view/menu/jh;)Landroidx/appcompat/view/menu/sh;

    move-result-object v1

    const/4 v2, 0x0

    const/4 v3, 0x0

    new-instance v4, Landroidx/appcompat/view/menu/hc0$a$f;

    const/4 v0, 0x0

    invoke-direct {v4, p0, p1, v0}, Landroidx/appcompat/view/menu/hc0$a$f;-><init>(Landroidx/appcompat/view/menu/hc0$a;Landroidx/appcompat/view/menu/q71;Landroidx/appcompat/view/menu/wg;)V

    const/4 v5, 0x3

    const/4 v6, 0x0

    invoke-static/range {v1 .. v6}, Landroidx/appcompat/view/menu/a9;->b(Landroidx/appcompat/view/menu/sh;Landroidx/appcompat/view/menu/jh;Landroidx/appcompat/view/menu/wh;Landroidx/appcompat/view/menu/xw;ILjava/lang/Object;)Landroidx/appcompat/view/menu/nk;

    move-result-object p1

    const/4 v1, 0x1

    invoke-static {p1, v0, v1, v0}, Landroidx/appcompat/view/menu/ih;->c(Landroidx/appcompat/view/menu/nk;Ljava/lang/Object;ILjava/lang/Object;)Landroidx/appcompat/view/menu/g90;

    move-result-object p1

    return-object p1
.end method
