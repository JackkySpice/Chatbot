.class public final Landroidx/appcompat/view/menu/p5$b;
.super Landroidx/appcompat/view/menu/xb$a;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Landroidx/appcompat/view/menu/p5;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "b"
.end annotation


# instance fields
.field public a:Landroidx/appcompat/view/menu/xb$b;

.field public b:Landroidx/appcompat/view/menu/b2;


# direct methods
.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Landroidx/appcompat/view/menu/xb$a;-><init>()V

    return-void
.end method


# virtual methods
.method public a()Landroidx/appcompat/view/menu/xb;
    .locals 4

    new-instance v0, Landroidx/appcompat/view/menu/p5;

    iget-object v1, p0, Landroidx/appcompat/view/menu/p5$b;->a:Landroidx/appcompat/view/menu/xb$b;

    iget-object v2, p0, Landroidx/appcompat/view/menu/p5$b;->b:Landroidx/appcompat/view/menu/b2;

    const/4 v3, 0x0

    invoke-direct {v0, v1, v2, v3}, Landroidx/appcompat/view/menu/p5;-><init>(Landroidx/appcompat/view/menu/xb$b;Landroidx/appcompat/view/menu/b2;Landroidx/appcompat/view/menu/p5$a;)V

    return-object v0
.end method

.method public b(Landroidx/appcompat/view/menu/b2;)Landroidx/appcompat/view/menu/xb$a;
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/p5$b;->b:Landroidx/appcompat/view/menu/b2;

    return-object p0
.end method

.method public c(Landroidx/appcompat/view/menu/xb$b;)Landroidx/appcompat/view/menu/xb$a;
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/p5$b;->a:Landroidx/appcompat/view/menu/xb$b;

    return-object p0
.end method
