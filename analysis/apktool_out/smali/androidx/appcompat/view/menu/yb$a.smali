.class public final Landroidx/appcompat/view/menu/yb$a;
.super Ljava/lang/Object;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Landroidx/appcompat/view/menu/yb;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "a"
.end annotation


# instance fields
.field public a:Landroidx/appcompat/view/menu/q01;

.field public b:Ljava/util/List;

.field public c:Landroidx/appcompat/view/menu/sx;

.field public d:Ljava/lang/String;


# direct methods
.method public constructor <init>()V
    .locals 2

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    iput-object v0, p0, Landroidx/appcompat/view/menu/yb$a;->a:Landroidx/appcompat/view/menu/q01;

    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    iput-object v1, p0, Landroidx/appcompat/view/menu/yb$a;->b:Ljava/util/List;

    iput-object v0, p0, Landroidx/appcompat/view/menu/yb$a;->c:Landroidx/appcompat/view/menu/sx;

    const-string v0, ""

    iput-object v0, p0, Landroidx/appcompat/view/menu/yb$a;->d:Ljava/lang/String;

    return-void
.end method


# virtual methods
.method public a(Landroidx/appcompat/view/menu/ga0;)Landroidx/appcompat/view/menu/yb$a;
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/yb$a;->b:Ljava/util/List;

    invoke-interface {v0, p1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    return-object p0
.end method

.method public b()Landroidx/appcompat/view/menu/yb;
    .locals 5

    new-instance v0, Landroidx/appcompat/view/menu/yb;

    iget-object v1, p0, Landroidx/appcompat/view/menu/yb$a;->a:Landroidx/appcompat/view/menu/q01;

    iget-object v2, p0, Landroidx/appcompat/view/menu/yb$a;->b:Ljava/util/List;

    invoke-static {v2}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object v2

    iget-object v3, p0, Landroidx/appcompat/view/menu/yb$a;->c:Landroidx/appcompat/view/menu/sx;

    iget-object v4, p0, Landroidx/appcompat/view/menu/yb$a;->d:Ljava/lang/String;

    invoke-direct {v0, v1, v2, v3, v4}, Landroidx/appcompat/view/menu/yb;-><init>(Landroidx/appcompat/view/menu/q01;Ljava/util/List;Landroidx/appcompat/view/menu/sx;Ljava/lang/String;)V

    return-object v0
.end method

.method public c(Ljava/lang/String;)Landroidx/appcompat/view/menu/yb$a;
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/yb$a;->d:Ljava/lang/String;

    return-object p0
.end method

.method public d(Landroidx/appcompat/view/menu/sx;)Landroidx/appcompat/view/menu/yb$a;
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/yb$a;->c:Landroidx/appcompat/view/menu/sx;

    return-object p0
.end method

.method public e(Landroidx/appcompat/view/menu/q01;)Landroidx/appcompat/view/menu/yb$a;
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/yb$a;->a:Landroidx/appcompat/view/menu/q01;

    return-object p0
.end method
