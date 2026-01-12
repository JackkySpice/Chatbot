.class public final Landroidx/appcompat/view/menu/jh$a$a;
.super Landroidx/appcompat/view/menu/d80;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/xw;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Landroidx/appcompat/view/menu/jh$a;->a(Landroidx/appcompat/view/menu/jh;Landroidx/appcompat/view/menu/jh;)Landroidx/appcompat/view/menu/jh;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = null
.end annotation


# static fields
.field public static final n:Landroidx/appcompat/view/menu/jh$a$a;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Landroidx/appcompat/view/menu/jh$a$a;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/jh$a$a;-><init>()V

    sput-object v0, Landroidx/appcompat/view/menu/jh$a$a;->n:Landroidx/appcompat/view/menu/jh$a$a;

    return-void
.end method

.method public constructor <init>()V
    .locals 1

    const/4 v0, 0x2

    invoke-direct {p0, v0}, Landroidx/appcompat/view/menu/d80;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final a(Landroidx/appcompat/view/menu/jh;Landroidx/appcompat/view/menu/jh$b;)Landroidx/appcompat/view/menu/jh;
    .locals 3

    const-string v0, "acc"

    invoke-static {p1, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "element"

    invoke-static {p2, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {p2}, Landroidx/appcompat/view/menu/jh$b;->getKey()Landroidx/appcompat/view/menu/jh$c;

    move-result-object v0

    invoke-interface {p1, v0}, Landroidx/appcompat/view/menu/jh;->j(Landroidx/appcompat/view/menu/jh$c;)Landroidx/appcompat/view/menu/jh;

    move-result-object p1

    sget-object v0, Landroidx/appcompat/view/menu/ao;->m:Landroidx/appcompat/view/menu/ao;

    if-ne p1, v0, :cond_0

    goto :goto_1

    :cond_0
    sget-object v1, Landroidx/appcompat/view/menu/zg;->b:Landroidx/appcompat/view/menu/zg$b;

    invoke-interface {p1, v1}, Landroidx/appcompat/view/menu/jh;->d(Landroidx/appcompat/view/menu/jh$c;)Landroidx/appcompat/view/menu/jh$b;

    move-result-object v2

    check-cast v2, Landroidx/appcompat/view/menu/zg;

    if-nez v2, :cond_1

    new-instance v0, Landroidx/appcompat/view/menu/cd;

    invoke-direct {v0, p1, p2}, Landroidx/appcompat/view/menu/cd;-><init>(Landroidx/appcompat/view/menu/jh;Landroidx/appcompat/view/menu/jh$b;)V

    :goto_0
    move-object p2, v0

    goto :goto_1

    :cond_1
    invoke-interface {p1, v1}, Landroidx/appcompat/view/menu/jh;->j(Landroidx/appcompat/view/menu/jh$c;)Landroidx/appcompat/view/menu/jh;

    move-result-object p1

    if-ne p1, v0, :cond_2

    new-instance p1, Landroidx/appcompat/view/menu/cd;

    invoke-direct {p1, p2, v2}, Landroidx/appcompat/view/menu/cd;-><init>(Landroidx/appcompat/view/menu/jh;Landroidx/appcompat/view/menu/jh$b;)V

    move-object p2, p1

    goto :goto_1

    :cond_2
    new-instance v0, Landroidx/appcompat/view/menu/cd;

    new-instance v1, Landroidx/appcompat/view/menu/cd;

    invoke-direct {v1, p1, p2}, Landroidx/appcompat/view/menu/cd;-><init>(Landroidx/appcompat/view/menu/jh;Landroidx/appcompat/view/menu/jh$b;)V

    invoke-direct {v0, v1, v2}, Landroidx/appcompat/view/menu/cd;-><init>(Landroidx/appcompat/view/menu/jh;Landroidx/appcompat/view/menu/jh$b;)V

    goto :goto_0

    :goto_1
    return-object p2
.end method

.method public bridge synthetic h(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Landroidx/appcompat/view/menu/jh;

    check-cast p2, Landroidx/appcompat/view/menu/jh$b;

    invoke-virtual {p0, p1, p2}, Landroidx/appcompat/view/menu/jh$a$a;->a(Landroidx/appcompat/view/menu/jh;Landroidx/appcompat/view/menu/jh$b;)Landroidx/appcompat/view/menu/jh;

    move-result-object p1

    return-object p1
.end method
