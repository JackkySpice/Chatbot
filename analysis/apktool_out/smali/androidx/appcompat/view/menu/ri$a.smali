.class public Landroidx/appcompat/view/menu/ri$a;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/h8$a;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Landroidx/appcompat/view/menu/ri;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field public final synthetic a:Landroidx/appcompat/view/menu/ri;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/ri;)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/ri$a;->a:Landroidx/appcompat/view/menu/ri;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public a(Ljava/nio/ByteBuffer;Landroidx/appcompat/view/menu/h8$b;)V
    .locals 1

    iget-object p2, p0, Landroidx/appcompat/view/menu/ri$a;->a:Landroidx/appcompat/view/menu/ri;

    sget-object v0, Landroidx/appcompat/view/menu/ex0;->b:Landroidx/appcompat/view/menu/ex0;

    invoke-virtual {v0, p1}, Landroidx/appcompat/view/menu/ex0;->c(Ljava/nio/ByteBuffer;)Ljava/lang/String;

    move-result-object p1

    invoke-static {p2, p1}, Landroidx/appcompat/view/menu/ri;->c(Landroidx/appcompat/view/menu/ri;Ljava/lang/String;)Ljava/lang/String;

    iget-object p1, p0, Landroidx/appcompat/view/menu/ri$a;->a:Landroidx/appcompat/view/menu/ri;

    invoke-static {p1}, Landroidx/appcompat/view/menu/ri;->d(Landroidx/appcompat/view/menu/ri;)Landroidx/appcompat/view/menu/ri$d;

    return-void
.end method
