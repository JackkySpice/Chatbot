.class public abstract Landroidx/appcompat/view/menu/ua;
.super Landroidx/appcompat/view/menu/ta;
.source "SourceFile"


# instance fields
.field public final d:Landroidx/appcompat/view/menu/xw;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/xw;Landroidx/appcompat/view/menu/jh;ILandroidx/appcompat/view/menu/t8;)V
    .locals 0

    invoke-direct {p0, p2, p3, p4}, Landroidx/appcompat/view/menu/ta;-><init>(Landroidx/appcompat/view/menu/jh;ILandroidx/appcompat/view/menu/t8;)V

    iput-object p1, p0, Landroidx/appcompat/view/menu/ua;->d:Landroidx/appcompat/view/menu/xw;

    return-void
.end method

.method public static synthetic j(Landroidx/appcompat/view/menu/ua;Landroidx/appcompat/view/menu/ck0;Landroidx/appcompat/view/menu/wg;)Ljava/lang/Object;
    .locals 0

    iget-object p0, p0, Landroidx/appcompat/view/menu/ua;->d:Landroidx/appcompat/view/menu/xw;

    invoke-interface {p0, p1, p2}, Landroidx/appcompat/view/menu/xw;->h(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    invoke-static {}, Landroidx/appcompat/view/menu/y50;->c()Ljava/lang/Object;

    move-result-object p1

    if-ne p0, p1, :cond_0

    return-object p0

    :cond_0
    sget-object p0, Landroidx/appcompat/view/menu/n31;->a:Landroidx/appcompat/view/menu/n31;

    return-object p0
.end method


# virtual methods
.method public e(Landroidx/appcompat/view/menu/ck0;Landroidx/appcompat/view/menu/wg;)Ljava/lang/Object;
    .locals 0

    invoke-static {p0, p1, p2}, Landroidx/appcompat/view/menu/ua;->j(Landroidx/appcompat/view/menu/ua;Landroidx/appcompat/view/menu/ck0;Landroidx/appcompat/view/menu/wg;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    const-string v1, "block["

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Landroidx/appcompat/view/menu/ua;->d:Landroidx/appcompat/view/menu/xw;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, "] -> "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-super {p0}, Landroidx/appcompat/view/menu/ta;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
