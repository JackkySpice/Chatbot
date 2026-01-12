.class public abstract Landroidx/appcompat/view/menu/na0;
.super Landroidx/appcompat/view/menu/mh;
.source "SourceFile"


# direct methods
.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Landroidx/appcompat/view/menu/mh;-><init>()V

    return-void
.end method


# virtual methods
.method public abstract F()Landroidx/appcompat/view/menu/na0;
.end method

.method public final G()Ljava/lang/String;
    .locals 2

    invoke-static {}, Landroidx/appcompat/view/menu/em;->c()Landroidx/appcompat/view/menu/na0;

    move-result-object v0

    if-ne p0, v0, :cond_0

    const-string v0, "Dispatchers.Main"

    return-object v0

    :cond_0
    const/4 v1, 0x0

    :try_start_0
    invoke-virtual {v0}, Landroidx/appcompat/view/menu/na0;->F()Landroidx/appcompat/view/menu/na0;

    move-result-object v0
    :try_end_0
    .catch Ljava/lang/UnsupportedOperationException; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    :catch_0
    move-object v0, v1

    :goto_0
    if-ne p0, v0, :cond_1

    const-string v0, "Dispatchers.Main.immediate"

    return-object v0

    :cond_1
    return-object v1
.end method
